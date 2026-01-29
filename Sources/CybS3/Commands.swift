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
            print("🔐 Login to CybS3")
            print(
                "This will store your mnemonic in the system Keychain so you don't have to type it every time."
            )

            do {
                let mnemonic = try InteractionService.promptForMnemonic(purpose: "login")

                // Verify it works by trying to load config?
                // If it's a new user, load() creates a new config.
                // If existing user, load() checks if it decrypts.
                _ = try StorageService.load(mnemonic: mnemonic)

                try KeychainService.save(mnemonic: mnemonic)
                print("✅ Login successful. Mnemonic stored in Keychain.")
            } catch {
                print("❌ Login failed: \(error)")
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
                print("✅ Logout successful. Mnemonic removed from Keychain.")
            } catch {
                print("❌ Logout failed or no active session: \(error)")
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
                let (client, _, _, vaultName, _) = try GlobalOptions.createClient(
                    options, overrideBucket: bucketName)
                print("Using vault: \(vaultName ?? "default") and bucket: \(bucketName)")
                try await client.createBucket(name: bucketName)
                print("Created bucket: \(bucketName)")
            }
        }

        struct List: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "list",
                abstract: "List all buckets"
            )

            @OptionGroup var options: GlobalOptions

            func run() async throws {
                let (client, _, _, vaultName, _) = try GlobalOptions.createClient(options)
                print("Using vault: \(vaultName ?? "default")")
                let buckets = try await client.listBuckets()

                print("Buckets:")
                for bucket in buckets {
                    print("  \(bucket)")
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
            ]
        )

        struct List: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "list",
                abstract: "List files in a bucket"
            )

            @OptionGroup var options: GlobalOptions

            func run() async throws {
                var bucketName: String
                if let b = options.bucket {
                    bucketName = b
                } else {
                    bucketName = try InteractionService.promptForBucket()
                }
                let (client, _, _, vaultName, _) = try GlobalOptions.createClient(
                    options, overrideBucket: bucketName)
                print("Using vault: \(vaultName ?? "default") and bucket: \(bucketName)")
                let objects = try await client.listObjects()

                for object in objects {
                    print(object)
                }
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
                print("Using vault: \(vaultName ?? "default") and bucket: \(bucketName)")
                let local = localPath ?? key
                let outputPath = local
                let outputURL = URL(fileURLWithPath: outputPath)

                _ = FileManager.default.createFile(atPath: outputPath, contents: nil)
                let fileHandle = try FileHandle(forWritingTo: outputURL)

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

                try fileHandle.close()
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

            func run() async throws {
                var bucketName: String
                if let b = options.bucket {
                    bucketName = b
                } else {
                    bucketName = try InteractionService.promptForBucket()
                }
                let (client, dataKey, _, vaultName, _) = try GlobalOptions.createClient(
                    options, overrideBucket: bucketName)
                print("Using vault: \(vaultName ?? "default") and bucket: \(bucketName)")
                let fileURL = URL(fileURLWithPath: localPath)
                guard FileManager.default.fileExists(atPath: localPath) else {
                    print("Error: File not found: \(localPath)")
                    throw ExitCode.failure
                }

                let remoteKey = key ?? (localPath as NSString).lastPathComponent

                let fileSize =
                    try FileManager.default.attributesOfItem(atPath: fileURL.path)[.size] as? Int64
                    ?? 0

                let progressBar = ConsoleUI.ProgressBar(title: "Uploading \(remoteKey)")

                let fileHandle = try FileHandle(forReadingFrom: fileURL)

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

                // Overhead calculation
                let fullChunks = fileSize / Int64(StreamingEncryption.chunkSize)
                let remainingBytes = fileSize % Int64(StreamingEncryption.chunkSize)
                var totalEncryptedSize = fullChunks * Int64(StreamingEncryption.chunkSize + 28)
                if remainingBytes > 0 {
                    totalEncryptedSize += (remainingBytes + 28)
                }

                try await client.putObject(
                    key: remoteKey, stream: uploadStream, length: totalEncryptedSize)

                progressBar.complete()
                print("Uploaded \(localPath) as \(remoteKey)")
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
                    print("Are you sure you want to delete '\(key)'? [y/N] ", terminator: "")
                    fflush(stdout)
                    guard let input = readLine(), input.lowercased() == "y" else {
                        print("Operation aborted.")
                        return
                    }
                }

                let (client, _, _, vaultName, _) = try GlobalOptions.createClient(
                    options, overrideBucket: bucketName)
                print("Using vault: \(vaultName ?? "default") and bucket: \(bucketName)")
                try await client.deleteObject(key: key)
                print("Deleted \(key)")
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
            Config.self,
            Login.self,
            Logout.self,
            Keys.self,
            Vaults.self,
        ]
    )
}
