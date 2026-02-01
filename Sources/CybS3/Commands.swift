import ArgumentParser
import AsyncHTTPClient
import Crypto
import CybS3Lib
import Foundation
import NIO
import SwiftBIP39

/// Global options available to all subcommands.
struct GlobalOptions: ParsableArguments {
    @Option(name: .long, help: "Vault name")
    var vault: String?

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
    ///
    /// - Important: The caller is responsible for calling `client.shutdown()` when done to release HTTP resources.
    ///   Use `defer { try? await client.shutdown() }` after obtaining the client.
    static func createClient(_ options: GlobalOptions, overrideBucket: String? = nil) throws -> (
        S3Client, SymmetricKey, EncryptedConfig, String?, String?
    ) {
        // 1. Get Mnemonic (Environment > Keychain > Prompt)
        let mnemonic: [String]

        if let envMnemonic = ProcessInfo.processInfo.environment["CYBS3_MNEMONIC"] {
            mnemonic = envMnemonic.components(separatedBy: .whitespacesAndNewlines).filter {
                !$0.isEmpty
            }
        } else if let storedMnemonic = KeychainService.load() {
            // Determine if this is an interactive context or if we should be silent?
            // For now, if it's in Keychain, we use it transparently.
            mnemonic = storedMnemonic
        } else {
            mnemonic = try InteractionService.promptForMnemonic(
                purpose: "unlock configuration (or run 'cybs3 login' first)")
        }

        // 2. Load Config & Data Key
        let (config, dataKey) = try StorageService.load(mnemonic: mnemonic)

        // 3. Determine vault settings
        let vaultConfig: VaultConfig?
        if let vaultName = options.vault {
            guard let v = config.vaults.first(where: { $0.name == vaultName }) else {
                print(
                    "Vault '\(vaultName)' not found. Available vaults: \(config.vaults.map { $0.name }.joined(separator: ", "))"
                )
                throw ExitCode.failure
            }
            vaultConfig = v
        } else if let activeName = config.activeVaultName,
            let v = config.vaults.first(where: { $0.name == activeName })
        {
            vaultConfig = v
        } else {
            vaultConfig = nil  // use global settings
        }

        // 4. Resolve S3 settings
        // Hierarchy: CLI Args -> Env Vars -> Vault -> Config Settings

        let envAccessKey = ProcessInfo.processInfo.environment["AWS_ACCESS_KEY_ID"]
        let envSecretKey = ProcessInfo.processInfo.environment["AWS_SECRET_ACCESS_KEY"]
        let envRegion = ProcessInfo.processInfo.environment["AWS_REGION"]
        let envBucket = ProcessInfo.processInfo.environment["AWS_BUCKET"]

        let finalAccessKey =
            options.accessKey ?? envAccessKey ?? vaultConfig?.accessKey ?? config.settings
            .defaultAccessKey ?? ""
        let finalSecretKey =
            options.secretKey ?? envSecretKey ?? vaultConfig?.secretKey ?? config.settings
            .defaultSecretKey ?? ""

        // Default region logic
        let configRegion = vaultConfig?.region ?? config.settings.defaultRegion
        let finalRegion =
            options.region != nil ? options.region! : (envRegion ?? configRegion ?? "us-east-1")

        let finalBucket =
            overrideBucket ?? envBucket ?? vaultConfig?.bucket ?? config.settings.defaultBucket

        // Endpoint logic
        var host = vaultConfig?.endpoint ?? config.settings.defaultEndpoint ?? "s3.amazonaws.com"
        if let e = options.endpoint {
            host = e
        }

        // Parse host/port/ssl from string
        let endpointString = host.contains("://") ? host : "https://\(host)"
        guard let url = URL(string: endpointString) else {
            throw ExitCode.failure  // Invalid URL
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

        return (client, dataKey, config, vaultConfig?.name, finalBucket)
    }
}

@main
/// The main entry point for the CybS3 Command Line Interface.
///
/// CybS3 provides an S3-compatible object storage browser with client-side encryption capabilities.
struct CybS3: AsyncParsableCommand {
    // MARK: - Login Command (NEW)

    /// Command to log in (store mnemonic in Keychain).
    struct Login: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "login",
            abstract: "Authenticate and store your mnemonic securely in Keychain"
        )

        func run() async throws {
            ConsoleUI.header("Login to CybS3")
            ConsoleUI.info(
                "This will store your mnemonic in the system Keychain for seamless access."
            )
            print()

            do {
                let mnemonic = try InteractionService.promptForMnemonic(purpose: "login")

                // Verify it works by trying to load config
                // If it's a new user, load() creates a new config.
                // If existing user, load() checks if it decrypts.
                _ = try StorageService.load(mnemonic: mnemonic)

                try KeychainService.save(mnemonic: mnemonic)
                ConsoleUI.success("Login successful. Mnemonic stored securely in Keychain.")
                ConsoleUI.dim("You can now run commands without entering your mnemonic.")
            } catch let error as InteractionError {
                CLIError.from(error).printError()
                throw ExitCode.failure
            } catch let error as StorageError {
                CLIError.from(error).printError()
                throw ExitCode.failure
            } catch let error as KeychainError {
                ConsoleUI.error("Keychain error: \(error.localizedDescription)")
                throw ExitCode.failure
            } catch {
                ConsoleUI.error("Login failed: \(error.localizedDescription)")
                throw ExitCode.failure
            }
        }
    }

    // MARK: - Login Command (NEW)

    /// Command to log out (remove mnemonic from Keychain).
    struct Logout: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "logout",
            abstract: "Remove your mnemonic from Keychain"
        )

        func run() async throws {
            do {
                try KeychainService.delete()
                ConsoleUI.success("Logout successful. Mnemonic removed from Keychain.")
            } catch KeychainError.itemNotFound {
                ConsoleUI.warning("No active session found. Already logged out.")
            } catch {
                ConsoleUI.error("Logout failed: \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Buckets Command Group

    struct Buckets: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "buckets",
            abstract: "Manage S3 buckets",
            subcommands: [
                Create.self,
                List.self,
            ]
        )

        struct Create: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "create",
                abstract: "Create a new bucket"
            )

            @OptionGroup var options: GlobalOptions

            @Argument(help: "Bucket name")
            var bucketName: String

            func run() async throws {
                do {
                    let (client, _, _, vaultName, _) = try GlobalOptions.createClient(
                        options, overrideBucket: bucketName)
                    defer { Task { try? await client.shutdown() } }
                    ConsoleUI.dim("Using vault: \(vaultName ?? "default")")
                    try await client.createBucket(name: bucketName)
                    ConsoleUI.success("Created bucket: \(bucketName)")
                } catch let error as S3Error {
                    ConsoleUI.error(error.localizedDescription)
                    throw ExitCode.failure
                }
            }
        }
        
        struct Delete: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "delete",
                abstract: "Delete an empty bucket"
            )

            @OptionGroup var options: GlobalOptions

            @Argument(help: "Bucket name to delete")
            var bucketName: String
            
            @Flag(name: .shortAndLong, help: "Force delete without confirmation")
            var force: Bool = false

            func run() async throws {
                if !force {
                    ConsoleUI.warning("You are about to delete bucket '\(bucketName)'. This cannot be undone.")
                    guard InteractionService.confirm(message: "Are you sure?", defaultValue: false) else {
                        ConsoleUI.info("Operation cancelled.")
                        return
                    }
                }
                
                do {
                    let (client, _, _, vaultName, _) = try GlobalOptions.createClient(options)
                    defer { Task { try? await client.shutdown() } }
                    ConsoleUI.dim("Using vault: \(vaultName ?? "default")")
                    try await client.deleteBucket(name: bucketName)
                    ConsoleUI.success("Deleted bucket: \(bucketName)")
                } catch let error as S3Error {
                    ConsoleUI.error(error.localizedDescription)
                    throw ExitCode.failure
                }
            }
        }

        struct List: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "list",
                abstract: "List all buckets"
            )

            @OptionGroup var options: GlobalOptions
            
            @Flag(name: .long, help: "Output as JSON")
            var json: Bool = false

            func run() async throws {
                let (client, _, _, vaultName, _) = try GlobalOptions.createClient(options)
                defer { Task { try? await client.shutdown() } }
                if !json {
                    print("Using vault: \(vaultName ?? "default")")
                }
                let buckets = try await client.listBuckets()

                if json {
                    let encoder = JSONEncoder()
                    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                    let data = try encoder.encode(["buckets": buckets])
                    print(String(data: data, encoding: .utf8) ?? "[]")
                } else {
                    print("Buckets:")
                    for bucket in buckets {
                        print("  \(bucket)")
                    }
                }
            }
        }
    }

    // MARK: - Files Command Group

    struct Files: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "files",
            abstract: "Manage files in S3 buckets",
            subcommands: [
                List.self,
                Get.self,
                Put.self,
                Delete.self,
                Copy.self,
            ]
        )

        struct List: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "list",
                abstract: "List files in a bucket"
            )

            @OptionGroup var options: GlobalOptions
            
            @Option(name: .shortAndLong, help: "Filter by prefix (folder path)")
            var prefix: String?
            
            @Option(name: .shortAndLong, help: "Delimiter for grouping (e.g., '/')")
            var delimiter: String?
            
            @Flag(name: .long, help: "Output as JSON")
            var json: Bool = false

            func run() async throws {
                var bucketName: String
                if let b = options.bucket {
                    bucketName = b
                } else {
                    bucketName = try InteractionService.promptForBucket()
                }
                let (client, _, _, vaultName, _) = try GlobalOptions.createClient(
                    options, overrideBucket: bucketName)
                defer { Task { try? await client.shutdown() } }
                
                if !json {
                    print("Using vault: \(vaultName ?? "default") and bucket: \(bucketName)")
                    if let prefix = prefix {
                        print("Filtering by prefix: \(prefix)")
                    }
                }
                
                let objects = try await client.listObjects(prefix: prefix, delimiter: delimiter)

                if json {
                    let encoder = JSONEncoder()
                    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                    encoder.dateEncodingStrategy = .iso8601
                    
                    struct FileInfo: Encodable {
                        let key: String
                        let size: Int
                        let lastModified: Date
                        let isDirectory: Bool
                    }
                    
                    struct FilesOutput: Encodable {
                        let objects: [FileInfo]
                        let count: Int
                    }
                    
                    let fileInfos = objects.map { obj in
                        FileInfo(key: obj.key, size: obj.size, lastModified: obj.lastModified, isDirectory: obj.isDirectory)
                    }
                    let output = FilesOutput(objects: fileInfos, count: objects.count)
                    let data = try encoder.encode(output)
                    print(String(data: data, encoding: .utf8) ?? "{}")
                } else {
                    if objects.isEmpty {
                        print("No objects found.")
                    } else {
                        print("\nFound \(objects.count) object(s):")
                        print(String(repeating: "-", count: 60))
                        for object in objects {
                            print(object)
                        }
                    }
                }
            }
        }
        
        struct Copy: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "copy",
                abstract: "Copy a file within S3"
            )

            @OptionGroup var options: GlobalOptions

            @Argument(help: "Source file key")
            var sourceKey: String
            
            @Argument(help: "Destination file key")
            var destKey: String

            func run() async throws {
                var bucketName: String
                if let b = options.bucket {
                    bucketName = b
                } else {
                    bucketName = try InteractionService.promptForBucket()
                }
                let (client, _, _, vaultName, _) = try GlobalOptions.createClient(
                    options, overrideBucket: bucketName)
                defer { Task { try? await client.shutdown() } }
                print("Using vault: \(vaultName ?? "default") and bucket: \(bucketName)")
                
                try await client.copyObject(sourceKey: sourceKey, destKey: destKey)
                print("✅ Copied '\(sourceKey)' to '\(destKey)'")
            }
        }

        struct Get: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "get",
                abstract: "Download a file from a bucket"
            )

            @OptionGroup var options: GlobalOptions

            @Argument(help: "Remote file key")
            var key: String

            @Argument(help: "Local file path")
            var localPath: String?

            func run() async throws {
                var bucketName: String
                if let b = options.bucket {
                    bucketName = b
                } else {
                    bucketName = try InteractionService.promptForBucket()
                }
                let (client, dataKey, _, vaultName, _) = try GlobalOptions.createClient(
                    options, overrideBucket: bucketName)
                defer { Task { try? await client.shutdown() } }
                print("Using vault: \(vaultName ?? "default") and bucket: \(bucketName)")
                let local = localPath ?? key
                let outputPath = local
                let outputURL = URL(fileURLWithPath: outputPath)

                _ = FileManager.default.createFile(atPath: outputPath, contents: nil)
                let fileHandle = try FileHandle(forWritingTo: outputURL)
                defer { try? fileHandle.close() }

                // Get file size for progress bar
                let fileSize = try await client.getObjectSize(key: key) ?? 0
                let progressBar = ConsoleUI.ProgressBar(title: "Downloading \(key)")

                let encryptedStream = try await client.getObjectStream(key: key)
                let decryptedStream = StreamingEncryption.DecryptedStream(
                    upstream: encryptedStream, key: dataKey)

                var totalBytes = 0

                for try await chunk in decryptedStream {
                    totalBytes += chunk.count

                    if fileSize > 0 {
                        progressBar.update(progress: Double(totalBytes) / Double(fileSize))
                    } else {
                        // Indeterminate progress if size unknown
                        let mb = Double(totalBytes) / 1024 / 1024
                        print(String(format: "\rDownloaded: %.2f MB", mb), terminator: "")
                        fflush(stdout)
                    }

                    if #available(macOS 10.15.4, *) {
                        try fileHandle.seekToEnd()
                    } else {
                        fileHandle.seekToEndOfFile()
                    }
                    fileHandle.write(chunk)
                }

                if fileSize > 0 {
                    progressBar.complete()
                } else {
                    print()
                }

                print("Downloaded \(key) to \(local)")
            }
        }

        struct Put: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "put",
                abstract: "Upload a file to a bucket"
            )

            @OptionGroup var options: GlobalOptions

            @Argument(help: "Local file path")
            var localPath: String

            @Argument(help: "Remote file key")
            var key: String?
            
            @Flag(name: .long, help: "Show what would be uploaded without actually uploading")
            var dryRun: Bool = false

            func run() async throws {
                var bucketName: String
                if let b = options.bucket {
                    bucketName = b
                } else {
                    bucketName = try InteractionService.promptForBucket()
                }
                
                let fileURL = URL(fileURLWithPath: localPath)
                guard FileManager.default.fileExists(atPath: localPath) else {
                    ConsoleUI.error("File not found: \(localPath)")
                    throw ExitCode.failure
                }

                let remoteKey = key ?? (localPath as NSString).lastPathComponent

                let fileSize =
                    try FileManager.default.attributesOfItem(atPath: fileURL.path)[.size] as? Int64
                    ?? 0
                
                // Calculate encrypted size using the helper
                let encryptedSize = StreamingEncryption.encryptedSize(plaintextSize: fileSize)
                
                // Dry-run mode
                if dryRun {
                    print()
                    ConsoleUI.header("Dry Run - Upload Preview")
                    ConsoleUI.keyValue("Source:", localPath)
                    ConsoleUI.keyValue("Destination:", "s3://\(bucketName)/\(remoteKey)")
                    ConsoleUI.keyValue("Original size:", formatBytes(Int(fileSize)))
                    ConsoleUI.keyValue("Encrypted size:", formatBytes(Int(encryptedSize)))
                    ConsoleUI.keyValue("Overhead:", formatBytes(Int(encryptedSize - fileSize)))
                    print()
                    ConsoleUI.success("No changes made (dry-run mode)")
                    return
                }
                
                let (client, dataKey, _, vaultName, _) = try GlobalOptions.createClient(
                    options, overrideBucket: bucketName)
                defer { Task { try? await client.shutdown() } }
                print("Using vault: \(vaultName ?? "default") and bucket: \(bucketName)")

                let progressBar = ConsoleUI.ProgressBar(title: "Uploading \(remoteKey)")

                let fileHandle = try FileHandle(forReadingFrom: fileURL)
                defer { try? fileHandle.close() }

                // Track bytes read. Using a class to allow capture in closure.
                class ProgressTracker: @unchecked Sendable {
                    var totalBytes: Int64 = 0
                }
                let tracker = ProgressTracker()

                // Custom AsyncSequence to report progress
                let progressStream = FileHandleAsyncSequence(
                    fileHandle: fileHandle,
                    chunkSize: StreamingEncryption.chunkSize,
                    progress: { bytesRead in
                        tracker.totalBytes += Int64(bytesRead)
                        progressBar.update(progress: Double(tracker.totalBytes) / Double(fileSize))
                    }
                )

                // Encrypt using INTERNAL Data Key
                let encryptedStream = StreamingEncryption.EncryptedStream(
                    upstream: progressStream, key: dataKey)

                let uploadStream = encryptedStream.map { ByteBuffer(data: $0) }

                try await client.putObject(
                    key: remoteKey, stream: uploadStream, length: encryptedSize)

                progressBar.complete()
                ConsoleUI.success("Uploaded \(localPath) as \(remoteKey)")
            }
            
            private func formatBytes(_ bytes: Int) -> String {
                let units = ["B", "KB", "MB", "GB", "TB"]
                var size = Double(bytes)
                var unitIndex = 0
                
                while size >= 1024 && unitIndex < units.count - 1 {
                    size /= 1024
                    unitIndex += 1
                }
                
                return String(format: "%.2f %@", size, units[unitIndex])
            }
        }

        struct Delete: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "delete",
                abstract: "Delete a file from a bucket"
            )

            @OptionGroup var options: GlobalOptions

            @Argument(help: "File key to delete")
            var key: String

            @Flag(name: .shortAndLong, help: "Force delete without confirmation")
            var force: Bool = false

            func run() async throws {
                var bucketName: String
                if let b = options.bucket {
                    bucketName = b
                } else {
                    bucketName = try InteractionService.promptForBucket()
                }

                if !force {
                    ConsoleUI.warning("You are about to delete '\(key)' from bucket '\(bucketName)'.")
                    guard InteractionService.confirm(message: "Are you sure?", defaultValue: false) else {
                        ConsoleUI.info("Operation cancelled.")
                        return
                    }
                }

                let (client, _, _, vaultName, _) = try GlobalOptions.createClient(
                    options, overrideBucket: bucketName)
                defer { Task { try? await client.shutdown() } }
                ConsoleUI.dim("Using vault: \(vaultName ?? "default") and bucket: \(bucketName)")
                try await client.deleteObject(key: key)
                ConsoleUI.success("Deleted \(key)")
            }
        }
    }

    // MARK: - Config Command

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
            // Check keychain first, else prompt
            let mnemonic: [String]
            if let stored = KeychainService.load() {
                mnemonic = stored
            } else {
                mnemonic = try InteractionService.promptForMnemonic(purpose: "update configuration")
            }

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

    static let configuration = CommandConfiguration(
        commandName: "cybs3",
        abstract: "S3 Compatible Object Storage Browser",
        subcommands: [
            Buckets.self,
            Files.self,
            Folders.self,
            Config.self,
            Login.self,
            Logout.self,
            Keys.self,
            Vaults.self,
        ]
    )
}
