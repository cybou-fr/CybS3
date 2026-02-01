import AsyncHTTPClient
import NIOCore
import NIOFoundationCompat
import XCTest

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

    // MARK: - Full Lifecycle Test

    func testFullLifecycle() async throws {
        guard let creds = getTestCredentials() else {
            print("⏭️  Skipping Integration Tests: Environment variables not set.")
            print("   Required: IT_ENDPOINT, IT_REGION, IT_ACCESS_KEY, IT_SECRET_KEY")
            return
        }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)
        
        print("🧪 Starting Integration Test against \(creds.endpoint)")
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

        // 2. Verify bucket exists by listing buckets
        print("2️⃣  Verifying bucket exists")
        do {
            let buckets = try await client.listBuckets()
            XCTAssertTrue(buckets.contains(bucketName), "Created bucket should appear in list")
            print("   ✅ Bucket verified in list (\(buckets.count) total buckets)")
        } catch {
            XCTFail("Failed to list buckets: \(error)")
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
            // Cleanup bucket before returning
            try? await client.deleteBucket(name: bucketName)
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
            // Try to clean up copy if it was created
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

        print("🎉 Integration test completed successfully!")
    }
    
    // MARK: - Error Handling Tests
    
    func testNonExistentBucketError() async throws {
        guard let creds = getTestCredentials() else {
            print("⏭️  Skipping: Environment variables not set")
            return
        }
        
        let client = createClient(creds: creds, bucket: "this-bucket-definitely-does-not-exist-\(UUID().uuidString)")
        
        do {
            _ = try await client.listObjects(prefix: nil, delimiter: nil)
            XCTFail("Expected error for non-existent bucket")
        } catch let error as S3Error {
            // Expected - should be bucketNotFound or accessDenied
            switch error {
            case .bucketNotFound, .accessDenied:
                print("✅ Got expected error: \(error)")
            default:
                print("ℹ️  Got error (may be acceptable): \(error)")
            }
        } catch {
            print("ℹ️  Got non-S3 error: \(error)")
        }
    }
    
    func testNonExistentObjectError() async throws {
        guard let creds = getTestCredentials() else {
            print("⏭️  Skipping: Environment variables not set")
            return
        }
        
        // Use a known bucket or create one
        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)
        
        // Create bucket first
        try await client.createBucket(name: bucketName)
        
        defer {
            Task {
                try? await client.deleteBucket(name: bucketName)
            }
        }
        
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
    }
    
    // MARK: - Large File Test
    
    func testLargeFileUploadDownload() async throws {
        guard let creds = getTestCredentials() else {
            print("⏭️  Skipping: Environment variables not set")
            return
        }
        
        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)
        let objectKey = "large-test-file.bin"
        
        // Create bucket
        try await client.createBucket(name: bucketName)
        
        defer {
            Task {
                try? await client.deleteObject(key: objectKey)
                try? await client.deleteBucket(name: bucketName)
            }
        }
        
        // Create 5MB of test data
        let testSize = 5 * 1024 * 1024
        let testData = Data(repeating: 0xAB, count: testSize)
        
        print("📤 Uploading \(testSize / 1024 / 1024)MB file")
        
        // Upload in chunks
        let chunkSize = 1024 * 1024 // 1MB chunks
        let stream = AsyncStream<ByteBuffer> { continuation in
            var offset = 0
            while offset < testData.count {
                let end = min(offset + chunkSize, testData.count)
                let chunk = testData[offset..<end]
                continuation.yield(ByteBuffer(data: Data(chunk)))
                offset = end
            }
            continuation.finish()
        }
        
        try await client.putObject(key: objectKey, stream: stream, length: Int64(testSize))
        print("   ✅ Upload complete")
        
        // Download and verify
        print("📥 Downloading and verifying")
        let downloadStream = try await client.getObjectStream(key: objectKey)
        var downloadedData = Data()
        for try await chunk in downloadStream {
            downloadedData.append(chunk)
        }
        
        XCTAssertEqual(downloadedData.count, testSize, "Downloaded size should match")
        XCTAssertEqual(downloadedData, testData, "Downloaded data should match uploaded data")
        print("   ✅ Verification complete")
    }
}
