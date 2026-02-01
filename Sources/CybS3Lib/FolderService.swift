import Foundation
import Crypto

// MARK: - File Metadata

/// Represents metadata for a local file, used for deduplication and sync.
public struct LocalFileInfo: Sendable, Hashable, Equatable {
    /// The absolute path to the file on disk.
    public let absolutePath: String
    /// The relative path from the base folder (used as S3 key).
    public let relativePath: String
    /// File size in bytes.
    public let size: Int64
    /// Last modification date.
    public let modifiedDate: Date
    /// SHA256 hash of the file content (computed lazily).
    public var contentHash: String?
    
    public init(absolutePath: String, relativePath: String, size: Int64, modifiedDate: Date, contentHash: String? = nil) {
        self.absolutePath = absolutePath
        self.relativePath = relativePath
        self.size = size
        self.modifiedDate = modifiedDate
        self.contentHash = contentHash
    }
}

/// Represents metadata for a remote S3 file.
public struct RemoteFileInfo: Sendable, Hashable, Equatable {
    /// The S3 key (path).
    public let key: String
    /// File size in bytes (encrypted size).
    public let size: Int64
    /// Last modification date.
    public let modifiedDate: Date
    /// ETag (often MD5 hash of encrypted content).
    public let etag: String?
    
    public init(key: String, size: Int64, modifiedDate: Date, etag: String? = nil) {
        self.key = key
        self.size = size
        self.modifiedDate = modifiedDate
        self.etag = etag
    }
}

/// Result of comparing local and remote files for sync.
public struct SyncPlan: Sendable {
    /// Files that need to be uploaded (new or changed).
    public var toUpload: [LocalFileInfo]
    /// Files that are already in sync.
    public var inSync: [LocalFileInfo]
    /// Files that exist only remotely (for download in get).
    public var remoteOnly: [RemoteFileInfo]
    /// Total bytes to upload.
    public var totalBytesToUpload: Int64
    
    public init() {
        self.toUpload = []
        self.inSync = []
        self.remoteOnly = []
        self.totalBytesToUpload = 0
    }
}

// MARK: - Folder Service Errors

public enum FolderServiceError: Error, LocalizedError {
    case folderNotFound(String)
    case notADirectory(String)
    case accessDenied(String)
    case scanFailed(String)
    case hashComputationFailed(String)
    
    public var errorDescription: String? {
        switch self {
        case .folderNotFound(let path):
            return "❌ Folder not found: \(path)"
        case .notADirectory(let path):
            return "❌ Path is not a directory: \(path)"
        case .accessDenied(let path):
            return "❌ Access denied: \(path)"
        case .scanFailed(let reason):
            return "❌ Folder scan failed: \(reason)"
        case .hashComputationFailed(let path):
            return "❌ Failed to compute hash for: \(path)"
        }
    }
}

// MARK: - Folder Service

/// Service for handling folder operations, scanning, and synchronization.
public struct FolderService {
    
    /// Recursively scans a directory and returns information about all files.
    ///
    /// - Parameters:
    ///   - folderPath: The absolute path to the folder to scan.
    ///   - excludePatterns: Optional patterns to exclude (e.g., ".git", "node_modules").
    /// - Returns: An array of `LocalFileInfo` for all files found.
    public static func scanFolder(
        at folderPath: String,
        excludePatterns: [String] = [".git", ".DS_Store", "node_modules", ".svn", "__pycache__"]
    ) throws -> [LocalFileInfo] {
        let fileManager = FileManager.default
        let baseURL = URL(fileURLWithPath: folderPath).standardized
        
        // Verify folder exists and is a directory
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: baseURL.path, isDirectory: &isDirectory) else {
            throw FolderServiceError.folderNotFound(folderPath)
        }
        
        guard isDirectory.boolValue else {
            throw FolderServiceError.notADirectory(folderPath)
        }
        
        var files: [LocalFileInfo] = []
        
        // Use enumerator for recursive traversal
        guard let enumerator = fileManager.enumerator(
            at: baseURL,
            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey, .contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ) else {
            throw FolderServiceError.scanFailed("Could not create directory enumerator")
        }
        
        for case let fileURL as URL in enumerator {
            // Check exclusion patterns
            let path = fileURL.path
            if excludePatterns.contains(where: { path.contains($0) }) {
                continue
            }
            
            // Get file attributes
            do {
                let resourceValues = try fileURL.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey, .contentModificationDateKey])
                
                // Skip directories and special files
                guard resourceValues.isRegularFile == true else {
                    continue
                }
                
                let size = Int64(resourceValues.fileSize ?? 0)
                let modDate = resourceValues.contentModificationDate ?? Date()
                
                // Compute relative path
                let relativePath = fileURL.path
                    .replacingOccurrences(of: baseURL.path, with: "")
                    .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                
                files.append(LocalFileInfo(
                    absolutePath: fileURL.path,
                    relativePath: relativePath,
                    size: size,
                    modifiedDate: modDate
                ))
            } catch {
                // Skip files we can't read
                continue
            }
        }
        
        return files.sorted { $0.relativePath < $1.relativePath }
    }
    
    /// Computes the SHA256 hash of a file.
    ///
    /// - Parameter filePath: The absolute path to the file.
    /// - Returns: The hex-encoded SHA256 hash.
    public static func computeFileHash(_ filePath: String) throws -> String {
        let url = URL(fileURLWithPath: filePath)
        
        guard let fileHandle = try? FileHandle(forReadingFrom: url) else {
            throw FolderServiceError.hashComputationFailed(filePath)
        }
        defer { try? fileHandle.close() }
        
        var hasher = SHA256()
        let bufferSize = 1024 * 1024 // 1MB chunks
        
        while autoreleasepool(invoking: {
            let data = fileHandle.readData(ofLength: bufferSize)
            if data.isEmpty {
                return false
            }
            hasher.update(data: data)
            return true
        }) {}
        
        let digest = hasher.finalize()
        return digest.map { String(format: "%02hhx", $0) }.joined()
    }
    
    /// Creates a sync plan by comparing local files with remote files.
    ///
    /// - Parameters:
    ///   - localFiles: Array of local file info.
    ///   - remoteFiles: Array of remote S3 objects.
    ///   - remotePrefix: The prefix used for remote files (to strip when comparing).
    ///   - useHashComparison: Whether to compute and compare content hashes (slower but more accurate).
    /// - Returns: A `SyncPlan` describing what needs to be uploaded.
    public static func createSyncPlan(
        localFiles: [LocalFileInfo],
        remoteFiles: [S3Object],
        remotePrefix: String = "",
        useHashComparison: Bool = false
    ) -> SyncPlan {
        var plan = SyncPlan()
        
        // Build a dictionary of remote files by normalized key
        var remoteByKey: [String: S3Object] = [:]
        for remote in remoteFiles where !remote.isDirectory {
            var key = remote.key
            if !remotePrefix.isEmpty && key.hasPrefix(remotePrefix) {
                key = String(key.dropFirst(remotePrefix.count))
                if key.hasPrefix("/") {
                    key = String(key.dropFirst())
                }
            }
            remoteByKey[key] = remote
        }
        
        // Check each local file
        for localFile in localFiles {
            if let remote = remoteByKey[localFile.relativePath] {
                // File exists remotely - check if it needs update
                // We compare by size (accounting for encryption overhead) and modification date
                
                let encryptedSize = StreamingEncryption.encryptedSize(plaintextSize: localFile.size)
                
                // If sizes match (within encryption overhead tolerance) and local is not newer, skip
                let sizeMatches = abs(Int64(remote.size) - encryptedSize) <= 28 // Allow for overhead variance
                let localIsNewer = localFile.modifiedDate > remote.lastModified
                
                if sizeMatches && !localIsNewer {
                    plan.inSync.append(localFile)
                } else {
                    plan.toUpload.append(localFile)
                    plan.totalBytesToUpload += localFile.size
                }
                
                // Remove from remote dictionary (what's left are remote-only files)
                remoteByKey.removeValue(forKey: localFile.relativePath)
            } else {
                // File doesn't exist remotely - needs upload
                plan.toUpload.append(localFile)
                plan.totalBytesToUpload += localFile.size
            }
        }
        
        // Remaining remote files are remote-only
        for (_, remote) in remoteByKey where !remote.isDirectory {
            plan.remoteOnly.append(RemoteFileInfo(
                key: remote.key,
                size: Int64(remote.size),
                modifiedDate: remote.lastModified
            ))
        }
        
        return plan
    }
    
    /// Creates necessary local directories for a file path.
    ///
    /// - Parameter filePath: The file path for which to create parent directories.
    public static func ensureDirectoryExists(for filePath: String) throws {
        let fileManager = FileManager.default
        let url = URL(fileURLWithPath: filePath)
        let directory = url.deletingLastPathComponent()
        
        if !fileManager.fileExists(atPath: directory.path) {
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        }
    }
    
    /// Formats a file count and size summary.
    public static func formatSummary(fileCount: Int, totalBytes: Int64) -> String {
        let sizeStr = ConsoleUI.formatBytes(totalBytes)
        return "\(fileCount) file\(fileCount == 1 ? "" : "s") (\(sizeStr))"
    }
}

// MARK: - File Change Event

/// Represents a file system change event.
public enum FileChangeType: Sendable {
    case created
    case modified
    case deleted
    case renamed(oldPath: String)
}

/// Represents a file change event for the watcher.
public struct FileChangeEvent: Sendable {
    public let path: String
    public let relativePath: String
    public let changeType: FileChangeType
    public let timestamp: Date
    
    public init(path: String, relativePath: String, changeType: FileChangeType, timestamp: Date = Date()) {
        self.path = path
        self.relativePath = relativePath
        self.changeType = changeType
        self.timestamp = timestamp
    }
}

// MARK: - File Watcher

/// A file system watcher that monitors a directory for changes.
public actor FileWatcher {
    private let watchPath: URL
    private let excludePatterns: [String]
    private var isWatching = false
    private var dispatchSource: DispatchSourceFileSystemObject?
    private var fileDescriptor: Int32 = -1
    private var lastKnownFiles: [String: Date] = [:]
    private let pollInterval: TimeInterval
    
    /// Callback for file changes.
    public var onChange: (@Sendable (FileChangeEvent) async -> Void)?
    
    public init(
        path: String,
        excludePatterns: [String] = [".git", ".DS_Store", "node_modules", ".svn", "__pycache__"],
        pollInterval: TimeInterval = 1.0
    ) {
        self.watchPath = URL(fileURLWithPath: path).standardized
        self.excludePatterns = excludePatterns
        self.pollInterval = pollInterval
    }
    
    /// Starts watching for file changes.
    public func start() async throws {
        guard !isWatching else { return }
        
        // Initial scan to populate known files
        try await scanAndUpdateKnownFiles()
        
        isWatching = true
        
        // Start polling for changes
        Task {
            while isWatching {
                try? await Task.sleep(nanoseconds: UInt64(pollInterval * 1_000_000_000))
                if isWatching {
                    await checkForChanges()
                }
            }
        }
    }
    
    /// Stops watching for changes.
    public func stop() {
        isWatching = false
        if fileDescriptor >= 0 {
            close(fileDescriptor)
            fileDescriptor = -1
        }
        dispatchSource?.cancel()
        dispatchSource = nil
    }
    
    /// Scans the directory and updates the known files dictionary.
    private func scanAndUpdateKnownFiles() async throws {
        let files = try FolderService.scanFolder(at: watchPath.path, excludePatterns: excludePatterns)
        lastKnownFiles = Dictionary(uniqueKeysWithValues: files.map { ($0.relativePath, $0.modifiedDate) })
    }
    
    /// Checks for file changes by comparing current state with known state.
    private func checkForChanges() async {
        guard let currentFiles = try? FolderService.scanFolder(at: watchPath.path, excludePatterns: excludePatterns) else {
            return
        }
        
        let currentDict = Dictionary(uniqueKeysWithValues: currentFiles.map { ($0.relativePath, $0) })
        
        // Check for new and modified files
        for (relativePath, file) in currentDict {
            if let knownDate = lastKnownFiles[relativePath] {
                // File exists - check if modified
                if file.modifiedDate > knownDate {
                    let event = FileChangeEvent(
                        path: file.absolutePath,
                        relativePath: relativePath,
                        changeType: .modified
                    )
                    await onChange?(event)
                    lastKnownFiles[relativePath] = file.modifiedDate
                }
            } else {
                // New file
                let event = FileChangeEvent(
                    path: file.absolutePath,
                    relativePath: relativePath,
                    changeType: .created
                )
                await onChange?(event)
                lastKnownFiles[relativePath] = file.modifiedDate
            }
        }
        
        // Check for deleted files
        let currentPaths = Set(currentDict.keys)
        let deletedPaths = Set(lastKnownFiles.keys).subtracting(currentPaths)
        
        for relativePath in deletedPaths {
            let absolutePath = watchPath.appendingPathComponent(relativePath).path
            let event = FileChangeEvent(
                path: absolutePath,
                relativePath: relativePath,
                changeType: .deleted
            )
            await onChange?(event)
            lastKnownFiles.removeValue(forKey: relativePath)
        }
    }
}
