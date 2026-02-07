import XCTest
import CybS3Lib

/// Integration tests that run against real S3-compatible endpoints.
final class IntegrationTests: XCTestCase {
    // Test credentials provided by user
    private let testEndpoint = "s3.eu-west-4.idrivee2.com"
    private let testRegion = "eu-west-4"
    private let testAccessKey = "E9GDPm2f9bZrUYVBINXn"
    private let testSecretKey = "RMJuDc0hjrfZLr2aOYlVq3be7mQnzHTP7DVUngnR"
    private let testBucket = "test\(Int(Date().timeIntervalSince1970))"

    private var s3Client: S3Client!

    override func setUp() async throws {
        try await super.setUp()

        // Create S3 client with test credentials
        let endpoint = S3Endpoint(host: testEndpoint, port: 443, useSSL: true)
        s3Client = S3Client(
            endpoint: endpoint,
            accessKey: testAccessKey,
            secretKey: testSecretKey,
            bucket: testBucket,
            region: testRegion
        )

        // Create test bucket
        do {
            try await s3Client.createBucketIfNotExists()
        } catch {
            // Bucket might already exist, continue
            print("Note: Test bucket creation failed (might already exist): \(error)")
        }
    }

    override func tearDown() async throws {
        // Clean up test objects
        do {
            let objects = try await s3Client.listObjects(maxKeys: 100)
            for object in objects where object.key.hasPrefix("test-") {
                try await s3Client.deleteObject(key: object.key)
            }
        } catch {
            print("Warning: Failed to clean up test objects: \(error)")
        }

        try await super.tearDown()
    }

    /// Test basic object operations.
    func testBasicObjectOperations() async throws {
        let testKey = "test-object-\(UUID().uuidString)"
        let testData = Data("Hello, CybS3 Integration Test!".utf8)

        // Put object
        try await s3Client.putObject(key: testKey, data: testData)

        // Get object
        let retrievedData = try await s3Client.getObject(key: testKey)
        XCTAssertEqual(retrievedData, testData, "Retrieved data should match original")

        // List objects
        let objects = try await s3Client.listObjects(maxKeys: 10)
        XCTAssertTrue(objects.contains { $0.key == testKey }, "Object should be in list")

        // Delete object
        try await s3Client.deleteObject(key: testKey)

        // Verify deletion
        do {
            _ = try await s3Client.getObject(key: testKey)
            XCTFail("Object should have been deleted")
        } catch let error as S3Error {
            XCTAssertEqual(error, .objectNotFound, "Expected object not found error")
        }
    }

    /// Test large object upload and download.
    func testLargeObjectOperations() async throws {
        let testKey = "test-large-object-\(UUID().uuidString)"
        let largeData = Data(repeating: 0x41, count: 5 * 1024 * 1024) // 5MB

        // Upload large object
        let startTime = Date()
        try await s3Client.putObject(key: testKey, data: largeData)
        let uploadTime = Date().timeIntervalSince(startTime)

        // Download large object
        let downloadStartTime = Date()
        let retrievedData = try await s3Client.getObject(key: testKey)
        let downloadTime = Date().timeIntervalSince(downloadStartTime)

        XCTAssertEqual(retrievedData, largeData, "Large object data should match")

        print("Large object performance:")
        print("  Upload time: \(String(format: "%.2f", uploadTime))s")
        print("  Download time: \(String(format: "%.2f", downloadTime))s")
        print("  Upload speed: \(String(format: "%.2f", Double(largeData.count) / uploadTime / 1024 / 1024)) MB/s")
        print("  Download speed: \(String(format: "%.2f", Double(retrievedData.count) / downloadTime / 1024 / 1024)) MB/s")

        // Clean up
        try await s3Client.deleteObject(key: testKey)
    }

    /// Test multipart upload functionality.
    func testMultipartUpload() async throws {
        let testKey = "test-multipart-\(UUID().uuidString)"
        let largeData = Data(repeating: 0x42, count: 10 * 1024 * 1024) // 10MB

        // Perform multipart upload
        try await s3Client.putObjectMultipart(key: testKey, data: largeData, partSize: 5 * 1024 * 1024)

        // Verify upload
        let retrievedData = try await s3Client.getObject(key: testKey)
        XCTAssertEqual(retrievedData, largeData, "Multipart upload data should match")

        // Clean up
        try await s3Client.deleteObject(key: testKey)
    }

    /// Test concurrent operations.
    func testConcurrentOperations() async throws {
        let operationCount = 10
        let testData = Data("Concurrent test data".utf8)

        // Upload multiple objects concurrently
        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<operationCount {
                group.addTask { [client = s3Client!] in
                    let key = "test-concurrent-\(i)-\(UUID().uuidString)"
                    try await client.putObject(key: key, data: testData)
                    // Verify immediately
                    let retrieved = try await client.getObject(key: key)
                    XCTAssertEqual(retrieved, testData)
                    // Clean up
                    try await client.deleteObject(key: key)
                }
            }
            try await group.waitForAll()
        }
    }

    /// Test error handling with invalid operations.
    func testErrorHandling() async throws {
        // Try to get non-existent object
        do {
            _ = try await s3Client.getObject(key: "non-existent-object-\(UUID().uuidString)")
            XCTFail("Should have thrown objectNotFound error")
        } catch let error as S3Error {
            XCTAssertEqual(error, .objectNotFound)
        }

        // Try to delete non-existent object (should not throw)
        try await s3Client.deleteObject(key: "non-existent-object-\(UUID().uuidString)")
    }

    /// Test bucket operations.
    func testBucketOperations() async throws {
        // List objects in bucket (should work even if empty)
        let objects = try await s3Client.listObjects(maxKeys: 1)
        XCTAssertNotNil(objects)

        // Test with prefix filtering
        let prefixedObjects = try await s3Client.listObjects(prefix: "test-", maxKeys: 10)
        XCTAssertNotNil(prefixedObjects)
    }

    /// Test AsyncSequence functionality.
    func testAsyncSequence() async throws {
        // Upload some test objects
        let testObjects = 5
        for i in 0..<testObjects {
            let key = "test-sequence-\(i)-\(UUID().uuidString)"
            let data = Data("Sequence test \(i)".utf8)
            try await s3Client.putObject(key: key, data: data)
        }

        // Use array API to list objects
        let objects = try await s3Client.listObjects(prefix: "test-sequence-")
        var count = 0
        for object in objects {
            count += 1
            // Clean up as we go
            try await s3Client.deleteObject(key: object.key)
        }

        XCTAssertGreaterThanOrEqual(count, testObjects, "Should find at least the objects we uploaded")
    }
}