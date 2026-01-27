import Foundation
import ArgumentParser
import AsyncHTTPClient
import SwiftBIP39
import NIO
import Crypto

@main
/// The main entry point for the CybS3 Command Line Interface.
///
/// CybS3 provides an S3-compatible object storage browser with client-side encryption capabilities.
struct CybS3: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "cybs3",
        abstract: "S3 Compatible Object Storage Browser",
        subcommands: [
            List.self,
            Get.self,
            Put.self,
            Delete.self,
            Mb.self,
            Rb.self,
            Ls.self,
            Config.self,
            Keys.self,
            Vaults.self
        ],
        defaultSubcommand: Ls.self
    )
    
    /// Global options available to all subcommands.
    struct GlobalOptions: ParsableArguments {
        @Option(name: .shortAndLong, help: "S3 endpoint URL")
        var endpoint: String?
        
        @Option(name: .shortAndLong, help: "Access key")
        var accessKey: String?
        
        @Option(name: .shortAndLong, help: "Secret key")
        var secretKey: String?
        
        @Option(name: .shortAndLong, help: "Bucket name")
        var bucket: String?
        
        @Option(name: .shortAndLong, help: "Region")
        var region: String?
        
        @Flag(name: .long, inversion: .prefixedNo, help: "Use SSL")
        var ssl: Bool = true
        
        @Flag(name: .shortAndLong, help: "Verbose output")
        var verbose: Bool = false
        
        /// Creates a configured `S3Client`, resolving settings from CLI args, Environment variables, and the persisted Configuration.
        ///
        /// This method performs the following steps:
        /// 1. Prompts for the Master Key (Mnemonic) to unlock the encrypted configuration.
        /// 2. Loads the encrypted configuration and derives the Data Key.
        /// 3. Resolves S3 settings (Endpoint, Credentials, Region) with the hierarchy: CLI Args > Env Vars > Config.
        /// 4. Initializes and returns the `S3Client`, the Data Key (for encryption), and the full Config object.
        ///
        /// - Throws: `ExitCode.failure` if the URL is invalid or other setup errors occur.
        /// - Returns: A tuple containing the `S3Client`, the Symmetric `DataKey`, and the `EncryptedConfig`.
        func createClient() throws -> (S3Client, SymmetricKey, EncryptedConfig) {
            
            // 1. Prompt for Mnemonic to unlock Storage
            // NOTE: Ideally we would cache this in a session or env var, but for CLI we prompt per command unless passed via ENV.
            let mnemonic: [String]
            if let envMnemonic = ProcessInfo.processInfo.environment["CYBS3_MNEMONIC"] {
                 mnemonic = envMnemonic.components(separatedBy: .whitespacesAndNewlines).filter { !$0.isEmpty }
            } else {
                 mnemonic = try InteractionService.promptForMnemonic(purpose: "unlock configuration")
            }

            // 2. Load Config & Data Key
            let (config, dataKey) = try StorageService.load(mnemonic: mnemonic)
            
            // 3. Resolve S3 settings
            // Hierarchy: CLI Args -> Env Vars -> Config Settings
            
            let envAccessKey = ProcessInfo.processInfo.environment["AWS_ACCESS_KEY_ID"]
            let envSecretKey = ProcessInfo.processInfo.environment["AWS_SECRET_ACCESS_KEY"]
            let envRegion = ProcessInfo.processInfo.environment["AWS_REGION"]
            let envBucket = ProcessInfo.processInfo.environment["AWS_BUCKET"]
            
            let finalAccessKey = accessKey ?? envAccessKey ?? config.settings.defaultAccessKey ?? ""
            let finalSecretKey = secretKey ?? envSecretKey ?? config.settings.defaultSecretKey ?? ""
            
            // Default region logic
            let configRegion = config.settings.defaultRegion
            let finalRegion = region != nil ? region! : (envRegion ?? configRegion ?? "us-east-1")
            
            let finalBucket = bucket ?? envBucket ?? config.settings.defaultBucket
            
            // Endpoint logic
            var host = "s3.amazonaws.com"
            if let e = endpoint {
                host = e
            } else if let e = config.settings.defaultEndpoint {
                host = e
            }
            
            // Parse host/port/ssl from string
            let endpointString = host.contains("://") ? host : "https://\(host)"
            guard let url = URL(string: endpointString) else {
                throw ExitCode.failure // Invalid URL
            }
            
            let s3Endpoint = S3Endpoint(
                host: url.host ?? host,
                port: url.port ?? (url.scheme == "http" ? 80 : 443),
                useSSL: url.scheme == "https"
            )
            
            let client = S3Client(
                endpoint: s3Endpoint,
                accessKey: finalAccessKey,
                secretKey: finalSecretKey,
                bucket: finalBucket,
                region: finalRegion
            )
            
            return (client, dataKey, config)
        }
    }
}

// MARK: - List Command

extension CybS3 {
    /// Command to list all buckets.
    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "list",
            abstract: "List all buckets"
        )
        
        @OptionGroup var options: GlobalOptions
        
        func run() async throws {
            let (client, _, _) = try options.createClient()
            let buckets = try await client.listBuckets()
            
            print("Buckets:")
            for bucket in buckets {
                print("  \(bucket)")
            }
        }
    }
}

// MARK: - Get Command

extension CybS3 {
    /// Command to download an object from S3.
    ///
    /// The object is automatically decrypted using the Data Key derived from the user's Mnemonic.
    struct Get: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "get",
            abstract: "Download an object from S3 (Decrypted automatically)"
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Object key to download")
        var key: String
        
        @Option(name: .shortAndLong, help: "Output file path")
        var output: String?
        
        func run() async throws {
            let (client, dataKey, _) = try options.createClient()
            
            // Ensure bucket is selected
            // S3Client constructor handles this but check if needed
            
            let outputPath = output ?? FileManager.default.currentDirectoryPath + "/" + (key as NSString).lastPathComponent
            let outputURL = URL(fileURLWithPath: outputPath)
            
            _ = FileManager.default.createFile(atPath: outputPath, contents: nil)
            let fileHandle = try FileHandle(forWritingTo: outputURL)
            
            print("Downloading and Decrypting \(key) to \(outputPath)...")
            var totalBytes = 0
            
            // Use INTERNAL Data Key for decryption
            
            let encryptedStream = try await client.getObjectStream(key: key)
            let decryptedStream = StreamingEncryption.DecryptedStream(upstream: encryptedStream, key: dataKey)
            
            for try await chunk in decryptedStream {
                totalBytes += chunk.count
                let mb = Double(totalBytes) / 1024 / 1024
                print(String(format: "\rDecrypted: %.2f MB", mb), terminator: "")
                
                if #available(macOS 10.15.4, *) {
                    try fileHandle.seekToEnd()
                } else {
                    fileHandle.seekToEndOfFile()
                }
                fileHandle.write(chunk)
            }
            
            try fileHandle.close()
            print("\nDownload Complete (Decrypted).")
        }
    }
}

// MARK: - Put Command

extension CybS3 {
    /// Command to upload a file to S3.
    ///
    /// The file is automatically encrypted client-side using the Data Key before being streamed to S3.
    struct Put: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "put",
            abstract: "Upload a file to S3 (Encrypted automatically)"
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Local file path to upload")
        var file: String
        
        @Argument(help: "S3 object key (optional)")
        var key: String?
        
        func run() async throws {
            let fileURL = URL(fileURLWithPath: file)
            guard FileManager.default.fileExists(atPath: file) else {
                print("Error: File not found: \(file)")
                throw ExitCode.failure
            }
            
            let (client, dataKey, _) = try options.createClient()
            
            let objectKey = key ?? fileURL.lastPathComponent
            
            print("Encrypting and Uploading \(file) to \(objectKey)...")
            
            let fileHandle = try FileHandle(forReadingFrom: fileURL)
            let fileSize = try FileManager.default.attributesOfItem(atPath: fileURL.path)[.size] as? Int64 ?? 0
            
            let fileStream = FileHandleAsyncSequence(fileHandle: fileHandle, chunkSize: StreamingEncryption.chunkSize, progress: nil) // 1MB chunks
            
            // Encrypt using INTERNAL Data Key
            let encryptedStream = StreamingEncryption.EncryptedStream(upstream: fileStream, key: dataKey)
            
            let uploadStream = encryptedStream.map { ByteBuffer(data: $0) }
            
            // Overhead calculation
            let fullChunks = fileSize / Int64(StreamingEncryption.chunkSize)
            let remainingBytes = fileSize % Int64(StreamingEncryption.chunkSize)
            var totalEncryptedSize = fullChunks * Int64(StreamingEncryption.chunkSize + 28)
            if remainingBytes > 0 {
                totalEncryptedSize += (remainingBytes + 28)
            }
            
            try await client.putObject(key: objectKey, stream: uploadStream, length: totalEncryptedSize)
            
            print("\nUpload Complete (Encrypted).")
        }
    }
}

// MARK: - Delete Command

extension CybS3 {
    /// Command to delete an object from S3.
    struct Delete: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "delete",
            abstract: "Delete an object from S3"
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Object key to delete")
        var key: String
        
        func run() async throws {
            let (client, _, _) = try options.createClient()
            try await client.deleteObject(key: key)
            print("Deleted \(key)")
        }
    }
}

// MARK: - Make Bucket Command

extension CybS3 {
    /// Command to create a new bucket.
    struct Mb: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "mb",
            abstract: "Create a new bucket"
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Bucket name to create")
        var bucket: String
        
        func run() async throws {
            let (client, _, _) = try options.createClient()
            try await client.createBucket(name: bucket)
            print("Created bucket: \(bucket)")
        }
    }
}

// MARK: - Remove Bucket Command

extension CybS3 {
    struct Rb: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "rb",
            abstract: "Remove a bucket (not implemented - requires bucket to be empty)"
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Bucket name to remove")
        var bucket: String
        
        func run() async throws {
            print("Note: Removing buckets requires the bucket to be empty first")
        }
    }
}

// MARK: - List Objects Command (default)

extension CybS3 {
    struct Ls: AsyncParsableCommand {
        // MARK: - List Objects Command (default)
        /// List objects in the configured bucket.
        /// This is the default command if none is specified.
        static let configuration = CommandConfiguration(
            commandName: "ls",
            abstract: "List objects in a bucket",
            shouldDisplay: false
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Path prefix (optional)")
        var path: String?
        
        func run() async throws {
             let (client, _, _) = try options.createClient()
            
            let objects = try await client.listObjects(prefix: path)
            
            for object in objects {
                print(object)
            }
        }
    }
}

// MARK: - Config Command

extension CybS3 {
    /// Command to update the local configuration (default region, bucket, keys, etc.).
    struct Config: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "config",
            abstract: "Configure CybS3 settings"
        )
        
        @Option(name: .shortAndLong, help: "Set access key")
        var accessKey: String?
        
        @Option(name: .shortAndLong, help: "Set secret key")
        var secretKey: String?
        
        @Option(name: .shortAndLong, help: "Set default endpoint")
        var endpoint: String?
        
        @Option(name: .shortAndLong, help: "Set default region")
        var region: String?
        
        @Option(name: .shortAndLong, help: "Set default bucket")
        var bucket: String?
        
        func run() async throws {
            let mnemonic = try InteractionService.promptForMnemonic(purpose: "update configuration")
            var (config, _) = try StorageService.load(mnemonic: mnemonic)
            
            var changed = false
            if let accessKey = accessKey {
                config.settings.defaultAccessKey = accessKey
                changed = true
            }
            if let secretKey = secretKey {
                config.settings.defaultSecretKey = secretKey
                changed = true
            }
            if let endpoint = endpoint {
                config.settings.defaultEndpoint = endpoint
                changed = true
            }
            if let region = region {
                config.settings.defaultRegion = region
                changed = true
            }
            if let bucket = bucket {
                config.settings.defaultBucket = bucket
                changed = true
            }
            
            if changed {
                try StorageService.save(config, mnemonic: mnemonic)
                print("Configuration saved.")
            } else {
                print("No changes made.")
            }
        }
    }
}