import XCTest
import Foundation
import Crypto
@testable import CybS3Lib

final class FolderServiceTests: XCTestCase {
    
    // MARK: - Test Fixtures
    
    var tempDirectory: URL!
    
    override func setUp() async throws {
        try await super.setUp()
        // Create a unique temporary directory for each test
        tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CybS3Tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
    }
    
    override func tearDown() async throws {
        // Clean up temporary directory
        if let tempDirectory = tempDirectory {
            try? FileManager.default.removeItem(at: tempDirectory)
        }
        try await super.tearDown()
    }
    
    // MARK: - Helper Methods
    
    func createTestFile(name: String, content: String, in directory: URL? = nil) throws -> URL {
        let dir = directory ?? tempDirectory!
        let fileURL = dir.appendingPathComponent(name)
        try content.write(to: fileURL, atomically: true, encoding: .utf8)
        return fileURL
    }
    
    func createSubdirectory(name: String, in directory: URL? = nil) throws -> URL {
        let dir = directory ?? tempDirectory!
        let subDir = dir.appendingPathComponent(name)
        try FileManager.default.createDirectory(at: subDir, withIntermediateDirectories: true)
        return subDir
    }
    
    // MARK: - LocalFileInfo Tests
    
    func testLocalFileInfoInit() {
        let info = LocalFileInfo(
            absolutePath: "/path/to/file.txt",
            relativePath: "file.txt",
            size: 1024,
            modifiedDate: Date(),
            contentHash: nil
        )
        
        XCTAssertEqual(info.absolutePath, "/path/to/file.txt")
        XCTAssertEqual(info.relativePath, "file.txt")
        XCTAssertEqual(info.size, 1024)
        XCTAssertNil(info.contentHash)
    }
    
    func testLocalFileInfoWithHash() {
        let info = LocalFileInfo(
            absolutePath: "/path/to/file.txt",
            relativePath: "file.txt",
            size: 1024,
            modifiedDate: Date(),
            contentHash: "abc123"
        )
        
        XCTAssertEqual(info.contentHash, "abc123")
    }
    
    func testLocalFileInfoEquatable() {
        let date = Date()
        let info1 = LocalFileInfo(
            absolutePath: "/path/file.txt",
            relativePath: "file.txt",
            size: 100,
            modifiedDate: date
        )
        let info2 = LocalFileInfo(
            absolutePath: "/path/file.txt",
            relativePath: "file.txt",
            size: 100,
            modifiedDate: date
        )
        
        XCTAssertEqual(info1, info2)
    }
    
    func testLocalFileInfoHashable() {
        let date = Date()
        let info = LocalFileInfo(
            absolutePath: "/path/file.txt",
            relativePath: "file.txt",
            size: 100,
            modifiedDate: date
        )
        
        var set = Set<LocalFileInfo>()
        set.insert(info)
        XCTAssertEqual(set.count, 1)
        
        // Same info should not increase set count
        set.insert(info)
        XCTAssertEqual(set.count, 1)
    }
    
    // MARK: - RemoteFileInfo Tests
    
    func testRemoteFileInfoInit() {
        let info = RemoteFileInfo(
            key: "folder/file.txt",
            size: 2048,
            modifiedDate: Date(),
            etag: "\"abc123\""
        )
        
        XCTAssertEqual(info.key, "folder/file.txt")
        XCTAssertEqual(info.size, 2048)
        XCTAssertEqual(info.etag, "\"abc123\"")
    }
    
    func testRemoteFileInfoWithoutEtag() {
        let info = RemoteFileInfo(
            key: "file.txt",
            size: 100,
            modifiedDate: Date()
        )
        
        XCTAssertNil(info.etag)
    }
    
    // MARK: - SyncPlan Tests
    
    func testSyncPlanInit() {
        let plan = SyncPlan()
        
        XCTAssertTrue(plan.toUpload.isEmpty)
        XCTAssertTrue(plan.inSync.isEmpty)
        XCTAssertTrue(plan.remoteOnly.isEmpty)
        XCTAssertEqual(plan.totalBytesToUpload, 0)
    }
    
    func testSyncPlanMutation() {
        var plan = SyncPlan()
        
        let file = LocalFileInfo(
            absolutePath: "/path/file.txt",
            relativePath: "file.txt",
            size: 500,
            modifiedDate: Date()
        )
        
        plan.toUpload.append(file)
        plan.totalBytesToUpload = file.size
        
        XCTAssertEqual(plan.toUpload.count, 1)
        XCTAssertEqual(plan.totalBytesToUpload, 500)
    }
    
    // MARK: - FolderServiceError Tests
    
    func testFolderServiceErrorDescriptions() {
        let errors: [FolderServiceError] = [
            .folderNotFound("/path/to/folder"),
            .notADirectory("/path/to/file"),
            .accessDenied("/path/to/protected"),
            .scanFailed("Permission denied"),
            .hashComputationFailed("/path/to/file.bin")
        ]
        
        for error in errors {
            XCTAssertNotNil(error.errorDescription)
            XCTAssertFalse(error.errorDescription!.isEmpty)
            XCTAssertTrue(error.errorDescription!.contains("❌"))
        }
    }
    
    func testFolderNotFoundErrorContainsPath() {
        let error = FolderServiceError.folderNotFound("/some/missing/path")
        XCTAssertTrue(error.errorDescription!.contains("/some/missing/path"))
    }
    
    func testNotADirectoryErrorContainsPath() {
        let error = FolderServiceError.notADirectory("/path/to/file.txt")
        XCTAssertTrue(error.errorDescription!.contains("/path/to/file.txt"))
    }
    
    func testAccessDeniedErrorContainsPath() {
        let error = FolderServiceError.accessDenied("/protected/folder")
        XCTAssertTrue(error.errorDescription!.contains("/protected/folder"))
    }
    
    func testScanFailedErrorContainsReason() {
        let error = FolderServiceError.scanFailed("Disk full")
        XCTAssertTrue(error.errorDescription!.contains("Disk full"))
    }
    
    func testHashComputationFailedErrorContainsPath() {
        let error = FolderServiceError.hashComputationFailed("/path/to/large.bin")
        XCTAssertTrue(error.errorDescription!.contains("/path/to/large.bin"))
    }
    
    // MARK: - FolderService.scanFolder Tests
    
    func testScanEmptyFolder() throws {
        let files = try FolderService.scanFolder(at: tempDirectory.path)
        XCTAssertTrue(files.isEmpty, "Empty folder should return empty array")
    }
    
    func testScanFolderWithSingleFile() throws {
        let _ = try createTestFile(name: "test.txt", content: "Hello, World!")
        
        let files = try FolderService.scanFolder(at: tempDirectory.path)
        
        XCTAssertEqual(files.count, 1)
        XCTAssertTrue(files[0].relativePath.hasSuffix("test.txt"))
        XCTAssertEqual(files[0].size, 13) // "Hello, World!" is 13 bytes
    }
    
    func testScanFolderWithMultipleFiles() throws {
        let _ = try createTestFile(name: "file1.txt", content: "Content 1")
        let _ = try createTestFile(name: "file2.txt", content: "Content 2")
        let _ = try createTestFile(name: "file3.txt", content: "Content 3")
        
        let files = try FolderService.scanFolder(at: tempDirectory.path)
        
        XCTAssertEqual(files.count, 3)
    }
    
    func testScanFolderRecursively() throws {
        // Create nested structure
        let _ = try createTestFile(name: "root.txt", content: "Root file")
        let subDir = try createSubdirectory(name: "subfolder")
        let _ = try createTestFile(name: "nested.txt", content: "Nested file", in: subDir)
        
        let files = try FolderService.scanFolder(at: tempDirectory.path)
        
        XCTAssertEqual(files.count, 2)
        
        let paths = files.map { $0.relativePath }
        XCTAssertTrue(paths.contains(where: { $0.hasSuffix("root.txt") }))
        XCTAssertTrue(paths.contains(where: { $0.contains("subfolder") && $0.hasSuffix("nested.txt") }))
    }
    
    func testScanFolderExcludesPatterns() throws {
        // Create files that should be excluded
        let gitDir = try createSubdirectory(name: ".git")
        let _ = try createTestFile(name: "config", content: "git config", in: gitDir)
        let _ = try createTestFile(name: "regular.txt", content: "Regular file")
        
        let files = try FolderService.scanFolder(
            at: tempDirectory.path,
            excludePatterns: [".git"]
        )
        
        XCTAssertEqual(files.count, 1)
        XCTAssertTrue(files[0].relativePath.hasSuffix("regular.txt"))
    }
    
    func testScanFolderExcludesNodeModules() throws {
        let nodeModules = try createSubdirectory(name: "node_modules")
        let _ = try createTestFile(name: "package.json", content: "{}", in: nodeModules)
        let _ = try createTestFile(name: "app.js", content: "console.log('app');")
        
        let files = try FolderService.scanFolder(at: tempDirectory.path)
        
        XCTAssertEqual(files.count, 1)
        XCTAssertTrue(files[0].relativePath.hasSuffix("app.js"))
    }
    
    func testScanFolderExcludesDSStore() throws {
        // .DS_Store is hidden and should be excluded by default
        let _ = try createTestFile(name: "visible.txt", content: "Visible")
        
        let files = try FolderService.scanFolder(at: tempDirectory.path)
        
        XCTAssertEqual(files.count, 1)
        XCTAssertFalse(files.contains(where: { $0.relativePath.contains(".DS_Store") }))
    }
    
    func testScanNonExistentFolderThrows() {
        let nonExistentPath = tempDirectory.appendingPathComponent("does_not_exist").path
        
        XCTAssertThrowsError(try FolderService.scanFolder(at: nonExistentPath)) { error in
            if case FolderServiceError.folderNotFound(let path) = error {
                XCTAssertEqual(path, nonExistentPath)
            } else {
                XCTFail("Expected folderNotFound error")
            }
        }
    }
    
    func testScanFileInsteadOfFolderThrows() throws {
        let filePath = try createTestFile(name: "file.txt", content: "Content")
        
        XCTAssertThrowsError(try FolderService.scanFolder(at: filePath.path)) { error in
            if case FolderServiceError.notADirectory = error {
                // Expected
            } else {
                XCTFail("Expected notADirectory error")
            }
        }
    }
    
    func testScanFolderWithCustomExcludePatterns() throws {
        let _ = try createTestFile(name: "app.swift", content: "swift code")
        let _ = try createTestFile(name: "app.swift.bak", content: "backup")
        let _ = try createTestFile(name: "temp.tmp", content: "temp data")
        
        let files = try FolderService.scanFolder(
            at: tempDirectory.path,
            excludePatterns: [".bak", ".tmp"]
        )
        
        XCTAssertEqual(files.count, 1)
        XCTAssertTrue(files[0].relativePath.hasSuffix("app.swift"))
    }
    
    // MARK: - File Size Tests
    
    func testScanFolderReportsCorrectFileSize() throws {
        let content = String(repeating: "A", count: 1000)
        let _ = try createTestFile(name: "sized.txt", content: content)
        
        let files = try FolderService.scanFolder(at: tempDirectory.path)
        
        XCTAssertEqual(files.count, 1)
        XCTAssertEqual(files[0].size, 1000)
    }
    
    func testScanFolderReportsZeroSizeForEmptyFile() throws {
        let _ = try createTestFile(name: "empty.txt", content: "")
        
        let files = try FolderService.scanFolder(at: tempDirectory.path)
        
        XCTAssertEqual(files.count, 1)
        XCTAssertEqual(files[0].size, 0)
    }
    
    // MARK: - Modification Date Tests
    
    func testScanFolderReportsModificationDate() throws {
        let before = Date()
        let _ = try createTestFile(name: "dated.txt", content: "Content")
        let after = Date()
        
        let files = try FolderService.scanFolder(at: tempDirectory.path)
        
        XCTAssertEqual(files.count, 1)
        XCTAssertGreaterThanOrEqual(files[0].modifiedDate, before.addingTimeInterval(-1))
        XCTAssertLessThanOrEqual(files[0].modifiedDate, after.addingTimeInterval(1))
    }
    
    // MARK: - Deep Nesting Tests
    
    func testScanDeeplyNestedFolder() throws {
        // Create a deeply nested structure
        var currentDir = tempDirectory!
        for i in 1...5 {
            currentDir = try createSubdirectory(name: "level\(i)", in: currentDir)
        }
        let _ = try createTestFile(name: "deep.txt", content: "Deep file", in: currentDir)
        
        let files = try FolderService.scanFolder(at: tempDirectory.path)
        
        XCTAssertEqual(files.count, 1)
        XCTAssertTrue(files[0].relativePath.contains("level1"))
        XCTAssertTrue(files[0].relativePath.contains("level5"))
        XCTAssertTrue(files[0].relativePath.hasSuffix("deep.txt"))
    }
    
    // MARK: - Special Characters Tests
    
    func testScanFolderWithSpacesInNames() throws {
        let _ = try createTestFile(name: "file with spaces.txt", content: "Content")
        
        let files = try FolderService.scanFolder(at: tempDirectory.path)
        
        XCTAssertEqual(files.count, 1)
        XCTAssertTrue(files[0].relativePath.contains("file with spaces"))
    }
    
    func testScanFolderWithUnicodeNames() throws {
        let _ = try createTestFile(name: "文件.txt", content: "Unicode content")
        let _ = try createTestFile(name: "émoji_🚀.txt", content: "Emoji file")
        
        let files = try FolderService.scanFolder(at: tempDirectory.path)
        
        XCTAssertEqual(files.count, 2)
    }
    
    // MARK: - Performance Tests
    
    func testScanFolderPerformanceWithManyFiles() throws {
        // Create 100 files
        for i in 1...100 {
            let _ = try createTestFile(name: "file_\(i).txt", content: "Content \(i)")
        }
        
        measure {
            let files = try? FolderService.scanFolder(at: tempDirectory.path)
            XCTAssertEqual(files?.count, 100)
        }
    }
}
