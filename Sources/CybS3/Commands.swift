import Foundation
import ArgumentParser
import AsyncHTTPClient
import SwiftBIP39
import NIO

@main
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
    
    struct GlobalOptions: ParsableArguments {
        @Option(name: .shortAndLong, help: "S3 endpoint URL")
        var endpoint: String = "s3.amazonaws.com"
        
        @Option(name: .shortAndLong, help: "Access key")
        var accessKey: String?
        
        @Option(name: .shortAndLong, help: "Secret key")
        var secretKey: String?
        
        @Option(name: .shortAndLong, help: "Bucket name")
        var bucket: String?
        
        @Option(name: .shortAndLong, help: "Region")
        var region: String = "us-east-1"
        
        @Flag(name: .long, inversion: .prefixedNo, help: "Use SSL")
        var ssl: Bool = true
        
        @Flag(name: .shortAndLong, help: "Verbose output")
        var verbose: Bool = false
        
        func createClient() throws -> S3Client {
            // Use ConfigService
            let config = try ConfigService.loadConfig()
            
            let endpointURL = URL(string: endpoint) ?? URL(string: "https://\(endpoint)")!
            let host = endpointURL.host ?? endpoint
            let port = endpointURL.port ?? (ssl ? 443 : 80)
            let useSSL = endpointURL.scheme == "https" || ssl
            
            let s3Endpoint = S3Endpoint(
                host: host,
                port: port,
                useSSL: useSSL
            )
            
            let envAccessKey = ProcessInfo.processInfo.environment["AWS_ACCESS_KEY_ID"]
            let envSecretKey = ProcessInfo.processInfo.environment["AWS_SECRET_ACCESS_KEY"]
            let envRegion = ProcessInfo.processInfo.environment["AWS_REGION"]
            let envBucket = ProcessInfo.processInfo.environment["AWS_BUCKET"]
            
            let finalAccessKey = accessKey ?? envAccessKey ?? config.accessKey ?? ""
            let finalSecretKey = secretKey ?? envSecretKey ?? config.secretKey ?? ""
            let finalRegion = region != "us-east-1" ? region : (envRegion ?? config.region ?? "us-east-1")
            let finalBucket = bucket ?? envBucket ?? config.bucket
            
            return S3Client(
                endpoint: s3Endpoint,
                accessKey: finalAccessKey,
                secretKey: finalSecretKey,
                bucket: finalBucket,
                region: finalRegion
            )
        }
    }
    
    struct AppConfig: Codable {
        var accessKey: String?
        var secretKey: String?
        var endpoint: String?
        var region: String?
        var bucket: String?
    }
}

// MARK: - List Command

extension CybS3 {
    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "list",
            abstract: "List all buckets"
        )
        
        @OptionGroup var options: GlobalOptions
        
        func run() async throws {
            let client = try options.createClient()
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
    struct Get: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "get",
            abstract: "Download an object from S3 (Decrypted by default)"
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Object key to download")
        var key: String
        
        @Option(name: .shortAndLong, help: "Output file path")
        var output: String?
        
        func run() async throws {
            guard options.bucket != nil else {
                print("Error: Bucket must be specified for get operation")
                throw ExitCode.failure
            }
            
            // 1. Prompt for mnemonic to transparently decrypt
            let mnemonic: [String]
            do {
                mnemonic = try InteractionService.promptForMnemonic(purpose: "decrypt this file")
            } catch {
                print("Error: \(error)")
                throw ExitCode.failure
            }
            
            let client = try options.createClient()
            let outputPath = output ?? FileManager.default.currentDirectoryPath + "/" + (key as NSString).lastPathComponent
            let outputURL = URL(fileURLWithPath: outputPath)
            
            // Create file if not exists or truncate
            _ = FileManager.default.createFile(atPath: outputPath, contents: nil)
            let fileHandle = try FileHandle(forWritingTo: outputURL)
            
            print("Downloading and Decrypting \(key) to \(outputPath)...")
            var totalBytes = 0
            
            let fileDecryptionKey = try EncryptionService.deriveKey(mnemonic: mnemonic)
            
            // Get raw encrypted stream
            let encryptedStream = try await client.getObjectStream(key: key)
            
            // Decrypt stream
            // Helper wrapper for the new S3Client stream type
            let decryptedStream = StreamingEncryption.DecryptedStream(upstream: encryptedStream, key: fileDecryptionKey)
            
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
    struct Put: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "put",
            abstract: "Upload a file to S3 (Encrypted by default)"
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Local file path to upload")
        var file: String
        
        @Argument(help: "S3 object key (optional)")
        var key: String?
        
        func run() async throws {
            guard options.bucket != nil else {
                print("Error: Bucket must be specified for put operation")
                throw ExitCode.failure
            }
            
            let fileURL = URL(fileURLWithPath: file)
            guard FileManager.default.fileExists(atPath: file) else {
                print("Error: File not found: \(file)")
                throw ExitCode.failure
            }
            
            // 1. Prompt for mnemonic to transparently encrypt
            let mnemonic: [String]
            do {
                 mnemonic = try InteractionService.promptForMnemonic(purpose: "encrypt this file")
            } catch {
                print("Error: \(error)")
                throw ExitCode.failure
            }
            
            let objectKey = key ?? fileURL.lastPathComponent
            let client = try options.createClient()
            
            print("Encrypting and Uploading \(file) to \(objectKey)...")
            
            let fileEncryptionKey = try EncryptionService.deriveKey(mnemonic: mnemonic)
            
            // 2. Prepare Encryption Stream
            let fileHandle = try FileHandle(forReadingFrom: fileURL)
            let fileSize = try FileManager.default.attributesOfItem(atPath: fileURL.path)[.size] as? Int64 ?? 0
            
            // Use FileHandleAsyncSequence from S3Client helpers
            let fileStream = FileHandleAsyncSequence(fileHandle: fileHandle, chunkSize: StreamingEncryption.chunkSize, progress: nil) // 1MB chunks
            
            // EncryptedStream yields Data
            let encryptedStream = StreamingEncryption.EncryptedStream(upstream: fileStream, key: fileEncryptionKey)
            
            // Map Data -> ByteBuffer for S3Client
            let uploadStream = encryptedStream.map { ByteBuffer(data: $0) }
            
            // Calculate total encrypted size
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
    struct Delete: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "delete",
            abstract: "Delete an object from S3"
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Object key to delete")
        var key: String
        
        func run() async throws {
            guard options.bucket != nil else {
                print("Error: Bucket must be specified for delete operation")
                throw ExitCode.failure
            }
            
            let client = try options.createClient()
            try await client.deleteObject(key: key)
            
            print("Deleted \(key)")
        }
    }
}

// MARK: - Make Bucket Command

extension CybS3 {
    struct Mb: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "mb",
            abstract: "Create a new bucket"
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Bucket name to create")
        var bucket: String
        
        func run() async throws {
            let client = try options.createClient()
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
            print("Use: cybs3 list to see objects, then delete them before removing bucket")
        }
    }
}

// MARK: - List Objects Command (default)

extension CybS3 {
    struct Ls: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "ls",
            abstract: "List objects in a bucket",
            shouldDisplay: false
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Path prefix (optional)")
        var path: String?
        
        func run() async throws {
            guard options.bucket != nil else {
                print("Error: Bucket must be specified")
                print("Use: cybs3 --bucket <bucket-name> ls")
                throw ExitCode.failure
            }
            
            let client = try options.createClient()
            let objects = try await client.listObjects(prefix: path)
            
            for object in objects {
                print(object)
            }
        }
    }
}

// MARK: - Config Command

extension CybS3 {
    struct Config: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "config",
            abstract: "Configure CybS3"
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
            var config = try ConfigService.loadConfig()
            
            if let accessKey = accessKey {
                config.accessKey = accessKey
            }
            
            if let secretKey = secretKey {
                config.secretKey = secretKey
            }
            
            if let endpoint = endpoint {
                config.endpoint = endpoint
            }
            
            if let region = region {
                config.region = region
            }
            
            if let bucket = bucket {
                config.bucket = bucket
            }
            
            // Use ConfigService
            try ConfigService.saveConfig(config)
            
            print("Configuration saved to \(ConfigService.configPath.path)")
        }
    }
}