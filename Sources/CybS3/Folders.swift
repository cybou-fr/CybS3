import ArgumentParser
import AsyncHTTPClient
@preconcurrency import Crypto
import CybS3Lib
import Foundation
import NIO

// MARK: - Folders Command Group

/// Commands for managing folders recursively in S3.
struct Folders: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "folders",
        abstract: "Manage folders recursively in S3 buckets",
        subcommands: [
            Put.self,
            Get.self,
            Watch.self,
            Sync.self,
        ]
    )

    // MARK: - Put Command

    /// Upload a local folder to S3 with deduplication.
    struct Put: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "put",
            abstract: "Upload a folder recursively to S3 with deduplication"
        )

        @OptionGroup var options: GlobalOptions

        @Argument(help: "Local folder path to upload")
        var localPath: String

        @Argument(help: "Remote S3 prefix (destination path)")
        var remotePrefix: String?

        @Flag(name: .long, help: "Show what would be uploaded without actually uploading")
        var dryRun: Bool = false

        @Flag(name: .long, help: "Force upload all files, ignoring deduplication")
        var force: Bool = false

        @Option(name: .long, help: "Exclude patterns (comma-separated, e.g., '.git,node_modules')")
        var exclude: String?

        @Flag(name: .long, help: "Output as JSON")
        var json: Bool = false

        func run() async throws {
            // Resolve local path
            let localURL = URL(fileURLWithPath: localPath).standardized
            let folderName = localURL.lastPathComponent
            let prefix = remotePrefix ?? folderName

            // Parse exclude patterns
            var excludePatterns = [".git", ".DS_Store", "node_modules", ".svn", "__pycache__"]
            if let exclude = exclude {
                excludePatterns.append(contentsOf: exclude.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) })
            }

            // Scan local folder
            if !json {
                ConsoleUI.info("Scanning folder: \(localPath)")
            }

            let localFiles: [LocalFileInfo]
            do {
                localFiles = try FolderService.scanFolder(at: localURL.path, excludePatterns: excludePatterns)
            } catch let error as FolderServiceError {
                ConsoleUI.error(error.localizedDescription)
                throw ExitCode.failure
            }

            if localFiles.isEmpty {
                if json {
                    print("{\"status\": \"empty\", \"message\": \"No files found in folder\"}")
                } else {
                    ConsoleUI.warning("No files found in folder: \(localPath)")
                }
                return
            }

            // Get bucket
            var bucketName: String
            if let b = options.bucket {
                bucketName = b
            } else {
                bucketName = try InteractionService.promptForBucket()
            }

            let (client, dataKey, _, vaultName, _) = try GlobalOptions.createClient(
                options, overrideBucket: bucketName)
            defer { Task { try? await client.shutdown() } }

            if !json {
                ConsoleUI.dim("Using vault: \(vaultName ?? "default") and bucket: \(bucketName)")
            }

            // Get remote files for deduplication
            var syncPlan: SyncPlan
            if force {
                // Force upload all
                syncPlan = SyncPlan()
                syncPlan.toUpload = localFiles
                syncPlan.totalBytesToUpload = localFiles.reduce(0) { $0 + $1.size }
            } else {
                // Fetch remote files for comparison
                if !json {
                    ConsoleUI.info("Checking remote files for deduplication...")
                }
                let remoteFiles = try await client.listObjects(prefix: prefix.isEmpty ? nil : prefix)
                syncPlan = FolderService.createSyncPlan(
                    localFiles: localFiles,
                    remoteFiles: remoteFiles,
                    remotePrefix: prefix
                )
            }

            // Output summary
            if json {
                let output: [String: Any] = [
                    "totalFiles": localFiles.count,
                    "toUpload": syncPlan.toUpload.count,
                    "inSync": syncPlan.inSync.count,
                    "totalBytesToUpload": syncPlan.totalBytesToUpload,
                    "dryRun": dryRun
                ]
                let jsonData = try JSONSerialization.data(withJSONObject: output, options: [.prettyPrinted, .sortedKeys])
                print(String(data: jsonData, encoding: .utf8) ?? "{}")
            } else {
                print()
                ConsoleUI.header("Upload Summary")
                ConsoleUI.keyValue("Source:", localPath)
                ConsoleUI.keyValue("Destination:", "s3://\(bucketName)/\(prefix)")
                ConsoleUI.keyValue("Total files:", "\(localFiles.count)")
                ConsoleUI.keyValue("To upload:", FolderService.formatSummary(fileCount: syncPlan.toUpload.count, totalBytes: syncPlan.totalBytesToUpload))
                ConsoleUI.keyValue("Already in sync:", "\(syncPlan.inSync.count) files")
                print()
            }

            if syncPlan.toUpload.isEmpty {
                if !json {
                    ConsoleUI.success("All files are already synchronized!")
                }
                return
            }

            // Dry run - show what would be uploaded
            if dryRun {
                if !json {
                    ConsoleUI.header("Files to Upload (Dry Run)")
                    for file in syncPlan.toUpload.prefix(20) {
                        print("  📄 \(file.relativePath) (\(ConsoleUI.formatBytes(file.size)))")
                    }
                    if syncPlan.toUpload.count > 20 {
                        ConsoleUI.dim("  ... and \(syncPlan.toUpload.count - 20) more files")
                    }
                    print()
                    ConsoleUI.success("No changes made (dry-run mode)")
                }
                return
            }

            // Upload files
            var uploadedCount = 0
            var failedCount = 0
            let totalCount = syncPlan.toUpload.count

            for file in syncPlan.toUpload {
                let remoteKey = prefix.isEmpty ? file.relativePath : "\(prefix)/\(file.relativePath)"

                do {
                    let fileURL = URL(fileURLWithPath: file.absolutePath)
                    let fileHandle = try FileHandle(forReadingFrom: fileURL)
                    defer { try? fileHandle.close() }

                    // Progress for individual file
                    class ProgressTracker: @unchecked Sendable {
                        var totalBytes: Int64 = 0
                    }
                    let tracker = ProgressTracker()

                    let progressStream = FileHandleAsyncSequence(
                        fileHandle: fileHandle,
                        chunkSize: StreamingEncryption.chunkSize,
                        progress: { bytesRead in
                            tracker.totalBytes += Int64(bytesRead)
                        }
                    )

                    let encryptedStream = StreamingEncryption.EncryptedStream(
                        upstream: progressStream, key: dataKey)

                    let uploadStream = encryptedStream.map { ByteBuffer(data: $0) }
                    let encryptedSize = StreamingEncryption.encryptedSize(plaintextSize: file.size)

                    if !json {
                        print("\r[\(uploadedCount + 1)/\(totalCount)] Uploading: \(file.relativePath)", terminator: "")
                    }

                    try await client.putObject(key: remoteKey, stream: uploadStream, length: encryptedSize)
                    uploadedCount += 1

                } catch {
                    failedCount += 1
                    if !json {
                        print()
                        ConsoleUI.error("Failed to upload \(file.relativePath): \(error.localizedDescription)")
                    }
                }
            }

            // Final summary
            if !json {
                print()
                print()
                if failedCount == 0 {
                    ConsoleUI.success("Successfully uploaded \(uploadedCount) files to s3://\(bucketName)/\(prefix)")
                } else {
                    ConsoleUI.warning("Uploaded \(uploadedCount) files, \(failedCount) failed")
                }
            }
        }
    }

    // MARK: - Get Command

    /// Download a folder from S3 recursively.
    struct Get: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "get",
            abstract: "Download a folder recursively from S3"
        )

        @OptionGroup var options: GlobalOptions

        @Argument(help: "Remote S3 prefix (source path)")
        var remotePrefix: String

        @Argument(help: "Local folder path (destination)")
        var localPath: String?

        @Flag(name: .long, help: "Show what would be downloaded without actually downloading")
        var dryRun: Bool = false

        @Flag(name: .long, help: "Overwrite existing local files")
        var overwrite: Bool = false

        @Flag(name: .long, help: "Output as JSON")
        var json: Bool = false

        func run() async throws {
            // Resolve local path
            let destFolder = localPath ?? (remotePrefix as NSString).lastPathComponent
            let localURL = URL(fileURLWithPath: destFolder).standardized

            // Get bucket
            var bucketName: String
            if let b = options.bucket {
                bucketName = b
            } else {
                bucketName = try InteractionService.promptForBucket()
            }

            let (client, dataKey, _, vaultName, _) = try GlobalOptions.createClient(
                options, overrideBucket: bucketName)
            defer { Task { try? await client.shutdown() } }

            if !json {
                ConsoleUI.dim("Using vault: \(vaultName ?? "default") and bucket: \(bucketName)")
                ConsoleUI.info("Listing remote files...")
            }

            // List remote files
            let remoteFiles = try await client.listObjects(prefix: remotePrefix)
            let filesToDownload = remoteFiles.filter { !$0.isDirectory }

            if filesToDownload.isEmpty {
                if json {
                    print("{\"status\": \"empty\", \"message\": \"No files found at remote prefix\"}")
                } else {
                    ConsoleUI.warning("No files found at: s3://\(bucketName)/\(remotePrefix)")
                }
                return
            }

            let totalSize = Int64(filesToDownload.reduce(0) { $0 + $1.size })

            // Output summary
            if json {
                let output: [String: Any] = [
                    "totalFiles": filesToDownload.count,
                    "totalBytes": totalSize,
                    "destination": localURL.path,
                    "dryRun": dryRun
                ]
                let jsonData = try JSONSerialization.data(withJSONObject: output, options: [.prettyPrinted, .sortedKeys])
                print(String(data: jsonData, encoding: .utf8) ?? "{}")
            } else {
                print()
                ConsoleUI.header("Download Summary")
                ConsoleUI.keyValue("Source:", "s3://\(bucketName)/\(remotePrefix)")
                ConsoleUI.keyValue("Destination:", localURL.path)
                ConsoleUI.keyValue("Files:", FolderService.formatSummary(fileCount: filesToDownload.count, totalBytes: totalSize))
                print()
            }

            // Dry run
            if dryRun {
                if !json {
                    ConsoleUI.header("Files to Download (Dry Run)")
                    for file in filesToDownload.prefix(20) {
                        print("  📄 \(file.key) (\(ConsoleUI.formatBytes(Int64(file.size))))")
                    }
                    if filesToDownload.count > 20 {
                        ConsoleUI.dim("  ... and \(filesToDownload.count - 20) more files")
                    }
                    print()
                    ConsoleUI.success("No changes made (dry-run mode)")
                }
                return
            }

            // Create destination folder
            try FileManager.default.createDirectory(at: localURL, withIntermediateDirectories: true)

            // Download files
            var downloadedCount = 0
            var skippedCount = 0
            var failedCount = 0
            let totalCount = filesToDownload.count

            for remoteFile in filesToDownload {
                // Compute local path by stripping the remote prefix
                var relativePath = remoteFile.key
                if relativePath.hasPrefix(remotePrefix) {
                    relativePath = String(relativePath.dropFirst(remotePrefix.count))
                    if relativePath.hasPrefix("/") {
                        relativePath = String(relativePath.dropFirst())
                    }
                }

                let localFilePath = localURL.appendingPathComponent(relativePath).path

                // Check if file exists
                if FileManager.default.fileExists(atPath: localFilePath) && !overwrite {
                    skippedCount += 1
                    continue
                }

                do {
                    // Ensure parent directory exists
                    try FolderService.ensureDirectoryExists(for: localFilePath)

                    // Download and decrypt
                    if !json {
                        print("\r[\(downloadedCount + skippedCount + 1)/\(totalCount)] Downloading: \(relativePath)", terminator: "")
                    }

                    _ = FileManager.default.createFile(atPath: localFilePath, contents: nil)
                    let fileHandle = try FileHandle(forWritingTo: URL(fileURLWithPath: localFilePath))
                    defer { try? fileHandle.close() }

                    let encryptedStream = try await client.getObjectStream(key: remoteFile.key)
                    let decryptedStream = StreamingEncryption.DecryptedStream(
                        upstream: encryptedStream, key: dataKey)

                    for try await chunk in decryptedStream {
                        if #available(macOS 10.15.4, *) {
                            try fileHandle.seekToEnd()
                        } else {
                            fileHandle.seekToEndOfFile()
                        }
                        fileHandle.write(chunk)
                    }

                    downloadedCount += 1

                } catch {
                    failedCount += 1
                    if !json {
                        print()
                        ConsoleUI.error("Failed to download \(remoteFile.key): \(error.localizedDescription)")
                    }
                }
            }

            // Final summary
            if !json {
                print()
                print()
                if failedCount == 0 {
                    ConsoleUI.success("Successfully downloaded \(downloadedCount) files to \(localURL.path)")
                    if skippedCount > 0 {
                        ConsoleUI.info("Skipped \(skippedCount) existing files (use --overwrite to replace)")
                    }
                } else {
                    ConsoleUI.warning("Downloaded \(downloadedCount) files, \(failedCount) failed, \(skippedCount) skipped")
                }
            }
        }
    }

    // MARK: - Watch Command

    /// Watch a folder for changes and automatically upload to S3.
    struct Watch: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "watch",
            abstract: "Watch a folder for changes and auto-upload to S3"
        )

        @OptionGroup var options: GlobalOptions

        @Argument(help: "Local folder path to watch")
        var localPath: String

        @Argument(help: "Remote S3 prefix (destination path)")
        var remotePrefix: String?

        @Option(name: .long, help: "Poll interval in seconds (default: 2)")
        var interval: Double = 2.0

        @Option(name: .long, help: "Exclude patterns (comma-separated)")
        var exclude: String?

        @Flag(name: .long, help: "Perform initial sync before watching")
        var initialSync: Bool = false

        func run() async throws {
            // Resolve paths
            let localURL = URL(fileURLWithPath: localPath).standardized
            let folderName = localURL.lastPathComponent
            let prefix = remotePrefix ?? folderName

            // Verify folder exists
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: localURL.path, isDirectory: &isDir), isDir.boolValue else {
                ConsoleUI.error("Folder not found: \(localPath)")
                throw ExitCode.failure
            }

            // Parse exclude patterns
            var excludePatterns = [".git", ".DS_Store", "node_modules", ".svn", "__pycache__"]
            if let exclude = exclude {
                excludePatterns.append(contentsOf: exclude.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) })
            }

            // Get bucket
            var bucketName: String
            if let b = options.bucket {
                bucketName = b
            } else {
                bucketName = try InteractionService.promptForBucket()
            }

            let (client, dataKey, _, vaultName, _) = try GlobalOptions.createClient(
                options, overrideBucket: bucketName)
            // Note: Don't defer shutdown here as we need long-running connection

            ConsoleUI.header("Folder Watch Mode")
            ConsoleUI.keyValue("Watching:", localURL.path)
            ConsoleUI.keyValue("Destination:", "s3://\(bucketName)/\(prefix)")
            ConsoleUI.keyValue("Vault:", vaultName ?? "default")
            ConsoleUI.keyValue("Poll interval:", "\(interval)s")
            print()

            // Initial sync if requested
            if initialSync {
                ConsoleUI.info("Performing initial sync...")
                let localFiles = try FolderService.scanFolder(at: localURL.path, excludePatterns: excludePatterns)
                let remoteFiles = try await client.listObjects(prefix: prefix.isEmpty ? nil : prefix)
                let syncPlan = FolderService.createSyncPlan(
                    localFiles: localFiles,
                    remoteFiles: remoteFiles,
                    remotePrefix: prefix
                )

                if !syncPlan.toUpload.isEmpty {
                    ConsoleUI.info("Uploading \(syncPlan.toUpload.count) files...")
                    for file in syncPlan.toUpload {
                        try await uploadFile(file: file, prefix: prefix, client: client, dataKey: dataKey)
                    }
                    ConsoleUI.success("Initial sync complete!")
                } else {
                    ConsoleUI.success("All files already in sync!")
                }
                print()
            }

            ConsoleUI.info("Watching for changes... (Press Ctrl+C to stop)")
            print()

            // Create file watcher
            let watcher = FileWatcher(path: localURL.path, excludePatterns: excludePatterns, pollInterval: interval)

            // Capture bucket name for use in closure
            let bucket = bucketName

            // Set up change handler
            await watcher.setOnChange { [prefix, dataKey, bucket] event in
                switch event.changeType {
                case .created, .modified:
                    let timestamp = DateFormatter.localizedString(from: event.timestamp, dateStyle: .none, timeStyle: .medium)
                    print("[\(timestamp)] 📝 Changed: \(event.relativePath)")

                    do {
                        // Get file info
                        let attrs = try FileManager.default.attributesOfItem(atPath: event.path)
                        let size = (attrs[.size] as? Int64) ?? 0
                        let modDate = (attrs[.modificationDate] as? Date) ?? Date()

                        let fileInfo = LocalFileInfo(
                            absolutePath: event.path,
                            relativePath: event.relativePath,
                            size: size,
                            modifiedDate: modDate
                        )

                        try await uploadFile(file: fileInfo, prefix: prefix, client: client, dataKey: dataKey)
                        ConsoleUI.success("  ↳ Uploaded to s3://\(bucket)/\(prefix)/\(event.relativePath)")
                    } catch {
                        ConsoleUI.error("  ↳ Upload failed: \(error.localizedDescription)")
                    }

                case .deleted:
                    let timestamp = DateFormatter.localizedString(from: event.timestamp, dateStyle: .none, timeStyle: .medium)
                    print("[\(timestamp)] 🗑️  Deleted: \(event.relativePath)")
                    // Optionally delete from S3 as well (could be a flag)

                case .renamed(let oldPath):
                    let timestamp = DateFormatter.localizedString(from: event.timestamp, dateStyle: .none, timeStyle: .medium)
                    print("[\(timestamp)] 📋 Renamed: \(oldPath) → \(event.relativePath)")
                }
            }

            // Start watching
            try await watcher.start()

            // Keep running until interrupted
            while true {
                try await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }

        /// Uploads a single file to S3.
        private func uploadFile(file: LocalFileInfo, prefix: String, client: S3Client, dataKey: SymmetricKey) async throws {
            let remoteKey = prefix.isEmpty ? file.relativePath : "\(prefix)/\(file.relativePath)"

            let fileURL = URL(fileURLWithPath: file.absolutePath)
            let fileHandle = try FileHandle(forReadingFrom: fileURL)
            defer { try? fileHandle.close() }

            let progressStream = FileHandleAsyncSequence(
                fileHandle: fileHandle,
                chunkSize: StreamingEncryption.chunkSize,
                progress: nil
            )

            let encryptedStream = StreamingEncryption.EncryptedStream(
                upstream: progressStream, key: dataKey)

            let uploadStream = encryptedStream.map { ByteBuffer(data: $0) }
            let encryptedSize = StreamingEncryption.encryptedSize(plaintextSize: file.size)

            try await client.putObject(key: remoteKey, stream: uploadStream, length: encryptedSize)
        }
    }

    // MARK: - Sync Command

    /// Bidirectional sync between local folder and S3.
    struct Sync: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "sync",
            abstract: "Synchronize a local folder with S3 (upload new/changed files)"
        )

        @OptionGroup var options: GlobalOptions

        @Argument(help: "Local folder path")
        var localPath: String

        @Argument(help: "Remote S3 prefix")
        var remotePrefix: String?

        @Flag(name: .long, help: "Show what would be synced without making changes")
        var dryRun: Bool = false

        @Flag(name: .long, help: "Delete remote files that don't exist locally")
        var delete: Bool = false

        @Option(name: .long, help: "Exclude patterns (comma-separated)")
        var exclude: String?

        func run() async throws {
            // Resolve paths
            let localURL = URL(fileURLWithPath: localPath).standardized
            let folderName = localURL.lastPathComponent
            let prefix = remotePrefix ?? folderName

            // Parse exclude patterns
            var excludePatterns = [".git", ".DS_Store", "node_modules", ".svn", "__pycache__"]
            if let exclude = exclude {
                excludePatterns.append(contentsOf: exclude.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) })
            }

            // Scan local folder
            ConsoleUI.info("Scanning local folder...")
            let localFiles = try FolderService.scanFolder(at: localURL.path, excludePatterns: excludePatterns)

            if localFiles.isEmpty {
                ConsoleUI.warning("No files found in local folder: \(localPath)")
                return
            }

            // Get bucket
            var bucketName: String
            if let b = options.bucket {
                bucketName = b
            } else {
                bucketName = try InteractionService.promptForBucket()
            }

            let (client, dataKey, _, vaultName, _) = try GlobalOptions.createClient(
                options, overrideBucket: bucketName)
            defer { Task { try? await client.shutdown() } }

            ConsoleUI.dim("Using vault: \(vaultName ?? "default") and bucket: \(bucketName)")
            ConsoleUI.info("Fetching remote file list...")

            // Get remote files
            let remoteFiles = try await client.listObjects(prefix: prefix.isEmpty ? nil : prefix)

            // Create sync plan
            let syncPlan = FolderService.createSyncPlan(
                localFiles: localFiles,
                remoteFiles: remoteFiles,
                remotePrefix: prefix
            )

            // Summary
            print()
            ConsoleUI.header("Sync Summary")
            ConsoleUI.keyValue("Local folder:", localURL.path)
            ConsoleUI.keyValue("Remote prefix:", "s3://\(bucketName)/\(prefix)")
            ConsoleUI.keyValue("Local files:", "\(localFiles.count)")
            ConsoleUI.keyValue("To upload:", FolderService.formatSummary(fileCount: syncPlan.toUpload.count, totalBytes: syncPlan.totalBytesToUpload))
            ConsoleUI.keyValue("In sync:", "\(syncPlan.inSync.count) files")
            if delete {
                ConsoleUI.keyValue("To delete:", "\(syncPlan.remoteOnly.count) files")
            }
            print()

            if syncPlan.toUpload.isEmpty && (!delete || syncPlan.remoteOnly.isEmpty) {
                ConsoleUI.success("Everything is in sync!")
                return
            }

            // Dry run
            if dryRun {
                if !syncPlan.toUpload.isEmpty {
                    ConsoleUI.header("Files to Upload (Dry Run)")
                    for file in syncPlan.toUpload.prefix(15) {
                        print("  📤 \(file.relativePath)")
                    }
                    if syncPlan.toUpload.count > 15 {
                        ConsoleUI.dim("  ... and \(syncPlan.toUpload.count - 15) more")
                    }
                }

                if delete && !syncPlan.remoteOnly.isEmpty {
                    print()
                    ConsoleUI.header("Files to Delete (Dry Run)")
                    for file in syncPlan.remoteOnly.prefix(15) {
                        print("  🗑️  \(file.key)")
                    }
                    if syncPlan.remoteOnly.count > 15 {
                        ConsoleUI.dim("  ... and \(syncPlan.remoteOnly.count - 15) more")
                    }
                }

                print()
                ConsoleUI.success("No changes made (dry-run mode)")
                return
            }

            // Upload files
            if !syncPlan.toUpload.isEmpty {
                var uploadedCount = 0
                var failedCount = 0

                for file in syncPlan.toUpload {
                    let remoteKey = prefix.isEmpty ? file.relativePath : "\(prefix)/\(file.relativePath)"

                    do {
                        let fileURL = URL(fileURLWithPath: file.absolutePath)
                        let fileHandle = try FileHandle(forReadingFrom: fileURL)
                        defer { try? fileHandle.close() }

                        let progressStream = FileHandleAsyncSequence(
                            fileHandle: fileHandle,
                            chunkSize: StreamingEncryption.chunkSize,
                            progress: nil
                        )

                        let encryptedStream = StreamingEncryption.EncryptedStream(
                            upstream: progressStream, key: dataKey)

                        let uploadStream = encryptedStream.map { ByteBuffer(data: $0) }
                        let encryptedSize = StreamingEncryption.encryptedSize(plaintextSize: file.size)

                        print("\r  Uploading: \(file.relativePath)", terminator: "")

                        try await client.putObject(key: remoteKey, stream: uploadStream, length: encryptedSize)
                        uploadedCount += 1

                    } catch {
                        failedCount += 1
                        print()
                        ConsoleUI.error("Failed to upload \(file.relativePath): \(error.localizedDescription)")
                    }
                }

                print()
                ConsoleUI.success("Uploaded \(uploadedCount) files")
                if failedCount > 0 {
                    ConsoleUI.warning("\(failedCount) files failed to upload")
                }
            }

            // Delete remote-only files if requested
            if delete && !syncPlan.remoteOnly.isEmpty {
                var deletedCount = 0

                for file in syncPlan.remoteOnly {
                    do {
                        try await client.deleteObject(key: file.key)
                        deletedCount += 1
                    } catch {
                        ConsoleUI.error("Failed to delete \(file.key): \(error.localizedDescription)")
                    }
                }

                ConsoleUI.success("Deleted \(deletedCount) remote files")
            }

            print()
            ConsoleUI.success("Sync complete!")
        }
    }
}

// MARK: - FileWatcher Extension for onChange setter

extension FileWatcher {
    /// Sets the onChange callback.
    public func setOnChange(_ handler: @escaping @Sendable (FileChangeEvent) async -> Void) {
        self.onChange = handler
    }
}
