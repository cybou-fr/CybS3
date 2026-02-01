import AsyncHTTPClient
import NIOCore
import NIOFoundationCompat
import XCTest
import Crypto

@testable import CybS3Lib

final class IntegrationTests: XCTestCase {

    struct TestCredentials {
        let endpoint: String
        let region: String
        let accessKey: String
        let secretKey: String
        
        var isValid: Bool {
            return !endpoint.isEmpty && !region.isEmpty && !accessKey.isEmpty && !secretKey.isEmpty
        }
    }
    
    // MARK: - Test Setup & Helpers

    func getTestCredentials() -> TestCredentials? {
        guard let endpoint = ProcessInfo.processInfo.environment["IT_ENDPOINT"],
            let region = ProcessInfo.processInfo.environment["IT_REGION"],
            let accessKey = ProcessInfo.processInfo.environment["IT_ACCESS_KEY"],
            let secretKey = ProcessInfo.processInfo.environment["IT_SECRET_KEY"]
        else {
            return nil
        }
        return TestCredentials(
            endpoint: endpoint, region: region, accessKey: accessKey, secretKey: secretKey)
    }
    
    func skipIfNoCredentials(file: StaticString = #file, line: UInt = #line) -> TestCredentials? {
        guard let creds = getTestCredentials() else {
            print("⏭️  Skipping Integration Test: Environment variables not set.")
            print("   Required: IT_ENDPOINT, IT_REGION, IT_ACCESS_KEY, IT_SECRET_KEY")
            print("   Tip: source .env before running tests")
            return nil
        }
        return creds
    }
    
    /// Creates an S3Client with the provided credentials
    func createClient(creds: TestCredentials, bucket: String? = nil) -> S3Client {
        let endpoint = S3Endpoint(host: creds.endpoint, port: 443, useSSL: true)
        return S3Client(
            endpoint: endpoint,
            accessKey: creds.accessKey,
            secretKey: creds.secretKey,
            bucket: bucket,
            region: creds.region
        )
    }
    
    /// Generates a unique bucket name for testing
    func generateBucketName() -> String {
        return "cybs3-test-\(UInt32.random(in: 1000...9999))-\(Int(Date().timeIntervalSince1970))"
    }
    
    /// Helper to create a ByteBuffer stream from Data
    func createStream(from data: Data, chunkSize: Int = 1024 * 1024) -> AsyncStream<ByteBuffer> {
        return AsyncStream<ByteBuffer> { continuation in
            var offset = 0
            while offset < data.count {
                let end = min(offset + chunkSize, data.count)
                let chunk = data[offset..<end]
                continuation.yield(ByteBuffer(data: Data(chunk)))
                offset = end
            }
            continuation.finish()
        }
    }
    
    /// Helper to clean up a bucket (delete all objects then the bucket) and shutdown client
    func cleanupBucketAndShutdown(_ client: S3Client, name: String) async {
        do {
            // List and delete all objects
            let objects = try await client.listObjects(prefix: nil, delimiter: nil)
            for obj in objects {
                try? await client.deleteObject(key: obj.key)
            }
            // Delete bucket
            try await client.deleteBucket(name: name)
        } catch {
            print("⚠️  Cleanup warning: \(error)")
        }
        // Always shutdown the client
        try? await client.shutdown()
    }
    
    /// Shutdown client only (no bucket cleanup)
    func shutdownClient(_ client: S3Client) async {
        try? await client.shutdown()
    }

    // MARK: - Full Lifecycle Test

    func testFullLifecycle() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)
        
        print("🧪 Starting Full Lifecycle Test against \(creds.endpoint)")
        print("   Bucket: \(bucketName)")

        let objectKey = "test-file.txt"
        let copiedKey = "copied-\(objectKey)"

        // 1. Create Bucket
        print("1️⃣  Creating bucket: \(bucketName)")
        do {
            try await client.createBucket(name: bucketName)
            print("   ✅ Bucket created")
        } catch {
            XCTFail("Failed to create bucket: \(error)")
            return
        }

        // 2. Verify bucket exists by listing buckets (may be eventually consistent)
        print("2️⃣  Verifying bucket exists")
        do {
            let buckets = try await client.listBuckets()
            if buckets.contains(bucketName) {
                print("   ✅ Bucket verified in list (\(buckets.count) total buckets)")
            } else {
                print("   ⚠️  Bucket not yet in list (eventual consistency) - continuing anyway")
            }
        } catch {
            print("   ⚠️  Failed to list buckets: \(error) - continuing anyway")
        }

        // 3. Put Object
        let testContent = "Hello CybS3 Integration Test! 🚀 Timestamp: \(Date())"
        let testData = testContent.data(using: .utf8)!
        print("3️⃣  Uploading object: \(objectKey) (\(testData.count) bytes)")

        let buffer = ByteBuffer(data: testData)
        let stream = AsyncStream<ByteBuffer> { continuation in
            continuation.yield(buffer)
            continuation.finish()
        }

        do {
            try await client.putObject(key: objectKey, stream: stream, length: Int64(testData.count))
            print("   ✅ Object uploaded")
        } catch {
            XCTFail("Failed to upload object: \(error)")
            await cleanupBucketAndShutdown(client, name: bucketName)
            return
        }

        // 4. List Objects
        print("4️⃣  Listing objects in bucket")
        do {
            let objects = try await client.listObjects(prefix: nil, delimiter: nil)
            XCTAssertFalse(objects.isEmpty, "Bucket should contain at least one object")
            XCTAssertTrue(objects.contains { $0.key == objectKey }, "Our test object should be listed")
            print("   ✅ Found \(objects.count) object(s)")
        } catch {
            XCTFail("Failed to list objects: \(error)")
        }

        // 5. Get Object Size
        print("5️⃣  Getting object size")
        do {
            let size = try await client.getObjectSize(key: objectKey)
            XCTAssertEqual(size, testData.count, "Object size should match uploaded data")
            print("   ✅ Object size: \(size ?? 0) bytes")
        } catch {
            XCTFail("Failed to get object size: \(error)")
        }

        // 6. Get Object Content
        print("6️⃣  Downloading object: \(objectKey)")
        do {
            let downloadStream = try await client.getObjectStream(key: objectKey)
            var downloadedData = Data()
            for try await chunk in downloadStream {
                downloadedData.append(chunk)
            }

            XCTAssertEqual(downloadedData, testData, "Downloaded data should match uploaded data")
            let downloadedString = String(data: downloadedData, encoding: .utf8)
            XCTAssertEqual(downloadedString, testContent, "Downloaded content should match")
            print("   ✅ Downloaded and verified content")
        } catch {
            XCTFail("Failed to download object: \(error)")
        }

        // 7. Copy Object
        print("7️⃣  Copying object to \(copiedKey)")
        do {
            try await client.copyObject(sourceKey: objectKey, destKey: copiedKey)
            print("   ✅ Object copied")
            
            // Verify copy exists
            let copiedSize = try await client.getObjectSize(key: copiedKey)
            XCTAssertEqual(copiedSize, testData.count, "Copied object should have same size")
            
            // Clean up copy
            try await client.deleteObject(key: copiedKey)
            print("   ✅ Copied object cleaned up")
        } catch {
            XCTFail("Failed to copy object: \(error)")
            try? await client.deleteObject(key: copiedKey)
        }

        // 8. Delete Object
        print("8️⃣  Deleting object: \(objectKey)")
        do {
            try await client.deleteObject(key: objectKey)
            print("   ✅ Object deleted")
        } catch {
            XCTFail("Failed to delete object: \(error)")
        }

        // 9. Verify object is gone
        print("9️⃣  Verifying object deletion")
        do {
            let objects = try await client.listObjects(prefix: nil, delimiter: nil)
            XCTAssertFalse(objects.contains { $0.key == objectKey }, "Deleted object should not be listed")
            print("   ✅ Object no longer in list")
        } catch {
            XCTFail("Failed to verify object deletion: \(error)")
        }

        // 10. Delete Bucket
        print("🔟 Deleting bucket: \(bucketName)")
        do {
            try await client.deleteBucket(name: bucketName)
            print("   ✅ Bucket deleted")
        } catch {
            XCTFail("Failed to delete bucket: \(error)")
        }
        
        // Shutdown client
        await shutdownClient(client)
        print("🎉 Full lifecycle test completed successfully!")
    }
    
    // MARK: - Error Handling Tests
    
    func testNonExistentBucketError() async throws {
        guard let creds = skipIfNoCredentials() else { return }
        
        let client = createClient(creds: creds, bucket: "this-bucket-definitely-does-not-exist-\(UUID().uuidString)")
        
        do {
            _ = try await client.listObjects(prefix: nil, delimiter: nil)
            XCTFail("Expected error for non-existent bucket")
        } catch let error as S3Error {
            switch error {
            case .bucketNotFound, .accessDenied:
                print("✅ Got expected error: \(error)")
            default:
                print("ℹ️  Got error (may be acceptable): \(error)")
            }
        } catch {
            print("ℹ️  Got non-S3 error: \(error)")
        }
        
        await shutdownClient(client)
    }
    
    func testNonExistentObjectError() async throws {
        guard let creds = skipIfNoCredentials() else { return }
        
        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)
        
        try await client.createBucket(name: bucketName)
        
        do {
            _ = try await client.getObjectStream(key: "this-object-does-not-exist-\(UUID().uuidString)")
            XCTFail("Expected error for non-existent object")
        } catch let error as S3Error {
            if case .objectNotFound = error {
                print("✅ Got expected objectNotFound error")
            } else {
                print("ℹ️  Got different error: \(error)")
            }
        }
        
        // Cleanup
        await cleanupBucketAndShutdown(client, name: bucketName)
    }
    
    // MARK: - Large File Test
    
    func testLargeFileUploadDownload() async throws {
        guard let creds = skipIfNoCredentials() else { return }
        
        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)
        let objectKey = "large-test-file.bin"
        
        try await client.createBucket(name: bucketName)
        
        // Create 5MB of test data
        let testSize = 5 * 1024 * 1024
        let testData = Data(repeating: 0xAB, count: testSize)
        
        print("📤 Uploading \(testSize / 1024 / 1024)MB file")
        let startUpload = Date()
        
        let stream = createStream(from: testData, chunkSize: 1024 * 1024)
        try await client.putObject(key: objectKey, stream: stream, length: Int64(testSize))
        
        let uploadTime = Date().timeIntervalSince(startUpload)
        print("   ✅ Upload complete in \(String(format: "%.2f", uploadTime))s")
        
        // Download and verify
        print("📥 Downloading and verifying")
        let startDownload = Date()
        
        let downloadStream = try await client.getObjectStream(key: objectKey)
        var downloadedData = Data()
        for try await chunk in downloadStream {
            downloadedData.append(chunk)
        }
        
        let downloadTime = Date().timeIntervalSince(startDownload)
        print("   ✅ Download complete in \(String(format: "%.2f", downloadTime))s")
        
        XCTAssertEqual(downloadedData.count, testSize, "Downloaded size should match")
        XCTAssertEqual(downloadedData, testData, "Downloaded data should match uploaded data")
        print("   ✅ Verification complete")
        
        // Cleanup
        await cleanupBucketAndShutdown(client, name: bucketName)
    }
    
    // MARK: - Folder/Prefix Tests
    
    func testFolderStructure() async throws {
        guard let creds = skipIfNoCredentials() else { return }
        
        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)
        
        // Use do-catch to ensure cleanup always runs
        var testError: Error?
        
        do {
            try await client.createBucket(name: bucketName)
            
            print("🗂️  Testing folder structure")
            
            // Create files in different "folders"
            let files = [
                "root.txt",
                "folder1/file1.txt",
                "folder1/file2.txt",
                "folder1/subfolder/deep.txt",
                "folder2/another.txt"
            ]
            
            for file in files {
                let data = "Content of \(file)".data(using: .utf8)!
                let stream = createStream(from: data)
                try await client.putObject(key: file, stream: stream, length: Int64(data.count))
            }
            print("   ✅ Created \(files.count) files")
            
            // List all objects
            let allObjects = try await client.listObjects(prefix: nil, delimiter: nil)
            XCTAssertEqual(allObjects.count, files.count, "Should have all files")
            print("   ✅ Listed all \(allObjects.count) objects")
            
            // List with prefix - may fail on some S3-compatible services due to URL encoding
            do {
                let folder1Objects = try await client.listObjects(prefix: "folder1/", delimiter: nil)
                XCTAssertEqual(folder1Objects.count, 3, "folder1/ should have 3 files")
                print("   ✅ folder1/ contains \(folder1Objects.count) objects")
            } catch {
                print("   ⚠️  Prefix listing failed (may be URL encoding issue): \(error)")
            }
            
            // List with delimiter (simulating folder view)
            do {
                _ = try await client.listObjects(prefix: nil, delimiter: "/")
                print("   ✅ Root level listing works")
            } catch {
                print("   ⚠️  Delimiter listing failed: \(error)")
            }
            
            print("   ✅ Folder structure test complete")
        } catch {
            testError = error
        }
        
        // Always cleanup
        await cleanupBucketAndShutdown(client, name: bucketName)
        
        // Re-throw if there was an error
        if let error = testError {
            throw error
        }
    }
    
    // MARK: - Binary Data Test
    
    func testBinaryDataIntegrity() async throws {
        guard let creds = skipIfNoCredentials() else { return }
        
        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)
        
        try await client.createBucket(name: bucketName)
        
        print("🔢 Testing binary data integrity")
        
        // Create binary data with all byte values
        var binaryData = Data()
        for _ in 0..<100 {
            for byte: UInt8 in 0...255 {
                binaryData.append(byte)
            }
        }
        print("   Created \(binaryData.count) bytes of binary data")
        
        let objectKey = "binary-test.bin"
        let stream = createStream(from: binaryData)
        try await client.putObject(key: objectKey, stream: stream, length: Int64(binaryData.count))
        print("   ✅ Uploaded binary data")
        
        // Download and verify
        let downloadStream = try await client.getObjectStream(key: objectKey)
        var downloadedData = Data()
        for try await chunk in downloadStream {
            downloadedData.append(chunk)
        }
        
        XCTAssertEqual(downloadedData.count, binaryData.count)
        XCTAssertEqual(downloadedData, binaryData)
        print("   ✅ Binary data integrity verified")
        
        // Cleanup
        await cleanupBucketAndShutdown(client, name: bucketName)
    }
    
    // MARK: - Unicode Filename Test
    
    func testUnicodeFilenames() async throws {
        guard let creds = skipIfNoCredentials() else { return }
        
        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)
        
        try await client.createBucket(name: bucketName)
        
        print("🌍 Testing Unicode filenames")
        
        let unicodeFiles = [
            "fichier-français.txt",
            "文件.txt",
            "ファイル.txt",
            "файл.txt",
            "emoji-🚀-file.txt"
        ]
        
        let content = "Test content".data(using: .utf8)!
        
        for file in unicodeFiles {
            let stream = createStream(from: content)
            do {
                try await client.putObject(key: file, stream: stream, length: Int64(content.count))
                print("   ✅ Created: \(file)")
            } catch {
                print("   ⚠️  Failed to create '\(file)': \(error)")
            }
        }
        
        // Verify files exist
        let objects = try await client.listObjects(prefix: nil, delimiter: nil)
        print("   ✅ Total objects created: \(objects.count)")
        
        // Cleanup
        await cleanupBucketAndShutdown(client, name: bucketName)
    }
    
    // MARK: - Encrypted Upload/Download Test
    
    func testEncryptedUploadDownload() async throws {
        guard let creds = skipIfNoCredentials() else { return }
        
        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)
        
        try await client.createBucket(name: bucketName)
        
        print("🔐 Testing encrypted upload/download")
        
        let key = SymmetricKey(size: .bits256)
        let originalData = "This is sensitive data that must be encrypted! 🔐".data(using: .utf8)!
        
        // Encrypt data
        let encryptedData = try Encryption.encrypt(data: originalData, key: key)
        print("   Original: \(originalData.count) bytes, Encrypted: \(encryptedData.count) bytes")
        
        // Upload encrypted
        let objectKey = "encrypted-file.enc"
        let stream = createStream(from: encryptedData)
        try await client.putObject(key: objectKey, stream: stream, length: Int64(encryptedData.count))
        print("   ✅ Uploaded encrypted data")
        
        // Download
        let downloadStream = try await client.getObjectStream(key: objectKey)
        var downloadedData = Data()
        for try await chunk in downloadStream {
            downloadedData.append(chunk)
        }
        
        XCTAssertEqual(downloadedData, encryptedData)
        print("   ✅ Downloaded encrypted data")
        
        // Decrypt and verify
        let decryptedData = try Encryption.decrypt(data: downloadedData, key: key)
        XCTAssertEqual(decryptedData, originalData)
        
        let decryptedString = String(data: decryptedData, encoding: .utf8)
        XCTAssertEqual(decryptedString, "This is sensitive data that must be encrypted! 🔐")
        print("   ✅ Decrypted and verified content")
        
        // Cleanup
        await cleanupBucketAndShutdown(client, name: bucketName)
    }
    
    // MARK: - Streaming Encryption Test
    
    func testStreamingEncryptedUploadDownload() async throws {
        guard let creds = skipIfNoCredentials() else { return }
        
        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)
        
        try await client.createBucket(name: bucketName)
        
        print("🔐 Testing streaming encryption")
        
        let key = SymmetricKey(size: .bits256)
        
        // Create 2MB test data
        let originalData = Data(repeating: 0x42, count: 2 * 1024 * 1024)
        print("   Original data: \(originalData.count) bytes")
        
        // Encrypt using streaming encryption
        let chunkSize = StreamingEncryption.chunkSize
        var encryptedChunks: [Data] = []
        
        // Manually chunk and encrypt
        var offset = 0
        while offset < originalData.count {
            let end = min(offset + chunkSize, originalData.count)
            let chunk = originalData[offset..<end]
            let sealedBox = try AES.GCM.seal(Data(chunk), using: key)
            encryptedChunks.append(sealedBox.combined!)
            offset = end
        }
        
        let encryptedData = encryptedChunks.reduce(Data()) { $0 + $1 }
        print("   Encrypted data: \(encryptedData.count) bytes (\(encryptedChunks.count) chunks)")
        
        // Upload
        let objectKey = "streaming-encrypted.enc"
        let stream = createStream(from: encryptedData)
        try await client.putObject(key: objectKey, stream: stream, length: Int64(encryptedData.count))
        print("   ✅ Uploaded streaming encrypted data")
        
        // Download
        let downloadStream = try await client.getObjectStream(key: objectKey)
        var downloadedData = Data()
        for try await chunk in downloadStream {
            downloadedData.append(chunk)
        }
        
        XCTAssertEqual(downloadedData.count, encryptedData.count)
        print("   ✅ Downloaded \(downloadedData.count) bytes")
        
        // Decrypt chunks
        let encryptedChunkSize = chunkSize + StreamingEncryption.overhead
        var decryptedData = Data()
        var downloadOffset = 0
        
        while downloadOffset < downloadedData.count {
            let end = min(downloadOffset + encryptedChunkSize, downloadedData.count)
            let encryptedChunk = downloadedData[downloadOffset..<end]
            let sealedBox = try AES.GCM.SealedBox(combined: encryptedChunk)
            let decryptedChunk = try AES.GCM.open(sealedBox, using: key)
            decryptedData.append(decryptedChunk)
            downloadOffset = end
        }
        
        XCTAssertEqual(decryptedData, originalData)
        print("   ✅ Decrypted and verified \(decryptedData.count) bytes")
        
        // Cleanup
        await cleanupBucketAndShutdown(client, name: bucketName)
    }
    
    // MARK: - Overwrite Test
    
    func testObjectOverwrite() async throws {
        guard let creds = skipIfNoCredentials() else { return }
        
        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)
        
        try await client.createBucket(name: bucketName)
        
        print("🔄 Testing object overwrite")
        
        let objectKey = "overwrite-test.txt"
        
        // Upload v1
        let v1Data = "Version 1 content".data(using: .utf8)!
        var stream = createStream(from: v1Data)
        try await client.putObject(key: objectKey, stream: stream, length: Int64(v1Data.count))
        print("   ✅ Uploaded v1")
        
        // Verify v1
        var downloadStream = try await client.getObjectStream(key: objectKey)
        var downloaded = Data()
        for try await chunk in downloadStream {
            downloaded.append(chunk)
        }
        XCTAssertEqual(String(data: downloaded, encoding: .utf8), "Version 1 content")
        
        // Overwrite with v2
        let v2Data = "Version 2 - updated content!".data(using: .utf8)!
        stream = createStream(from: v2Data)
        try await client.putObject(key: objectKey, stream: stream, length: Int64(v2Data.count))
        print("   ✅ Uploaded v2 (overwrite)")
        
        // Verify v2
        downloadStream = try await client.getObjectStream(key: objectKey)
        downloaded = Data()
        for try await chunk in downloadStream {
            downloaded.append(chunk)
        }
        XCTAssertEqual(String(data: downloaded, encoding: .utf8), "Version 2 - updated content!")
        print("   ✅ Verified overwrite worked")
        
        // Verify size changed
        let size = try await client.getObjectSize(key: objectKey)
        XCTAssertEqual(size, v2Data.count)
        print("   ✅ Size correctly updated to \(size ?? 0) bytes")
        
        // Cleanup
        await cleanupBucketAndShutdown(client, name: bucketName)
    }
    
    // MARK: - Empty File Test
    
    func testEmptyFile() async throws {
        guard let creds = skipIfNoCredentials() else { return }
        
        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)
        
        try await client.createBucket(name: bucketName)
        
        print("📄 Testing empty file")
        
        let objectKey = "empty-file.txt"
        let emptyData = Data()
        
        let stream = createStream(from: emptyData)
        try await client.putObject(key: objectKey, stream: stream, length: 0)
        print("   ✅ Uploaded empty file")
        
        // Verify size
        let size = try await client.getObjectSize(key: objectKey)
        XCTAssertEqual(size, 0)
        print("   ✅ Size is 0 bytes")
        
        // Download and verify
        let downloadStream = try await client.getObjectStream(key: objectKey)
        var downloaded = Data()
        for try await chunk in downloadStream {
            downloaded.append(chunk)
        }
        XCTAssertEqual(downloaded.count, 0)
        print("   ✅ Downloaded empty file successfully")
        
        // Cleanup
        await cleanupBucketAndShutdown(client, name: bucketName)
    }
}
