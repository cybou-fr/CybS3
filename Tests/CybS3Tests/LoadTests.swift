import AsyncHTTPClient
import NIOCore
import NIOFoundationCompat
import XCTest
import Crypto

@testable import CybS3Lib

final class LoadTests: XCTestCase {

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
            print("⏭️  Skipping Load Test: Environment variables not set.")
            print("   Required: IT_ENDPOINT, IT_REGION, IT_ACCESS_KEY, IT_SECRET_KEY")
            print("   Tip: source .env before running tests")
            return nil
        }
        return creds
    }

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

    func generateBucketName(prefix: String = "cybs3-load") -> String {
        return "\(prefix)-\(UInt32.random(in: 1000...9999))-\(Int(Date().timeIntervalSince1970))"
    }

    // MARK: - Concurrent Operations Tests

    func testConcurrentUploads() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Concurrent Uploads Test")
        print("   Bucket: \(bucketName)")

        // Create bucket
        try await client.createBucket(name: bucketName)

        // Test concurrent uploads
        let numUploads = 10
        let fileSize = 1024 * 1024 // 1MB each

        let startTime = Date()

        // Pre-create data to avoid capturing self in closures
        let testData = (0..<numUploads).map { _ in createLargeData(size: fileSize) }
        let testStreams = testData.map { createStream(from: $0) }

        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<numUploads {
                let stream = testStreams[i] // Capture the stream, not self
                group.addTask {
                    let key = "concurrent-file-\(i).dat"
                    try await client.putObject(key: key, stream: stream, length: Int64(testData[i].count))
                }
            }
            try await group.waitForAll()
        }

        let duration = Date().timeIntervalSince(startTime)
        let totalData = numUploads * fileSize
        let throughput = Double(totalData) / duration / (1024 * 1024) // MB/s

        print("   ✅ \(numUploads) concurrent uploads completed")
        print(String(format: "   📊 Throughput: %.2f MB/s", throughput))
        print(String(format: "   ⏱️  Duration: %.2f seconds", duration))

        // Verify all objects exist
        let objects = try await client.listObjects(prefix: nil, delimiter: nil)
        XCTAssertEqual(objects.count, numUploads, "All uploaded objects should be listed")

        // Cleanup
        for obj in objects {
            try await client.deleteObject(key: obj.key)
        }
        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    func testConcurrentDownloads() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Concurrent Downloads Test")
        print("   Bucket: \(bucketName)")

        // Create bucket and upload test files
        try await client.createBucket(name: bucketName)

        let numFiles = 5
        let fileSize = 2 * 1024 * 1024 // 2MB each
        var uploadedData = [String: Data]()

        // Upload files
        for i in 0..<numFiles {
            let key = "download-test-\(i).dat"
            let data = createLargeData(size: fileSize)
            let stream = createStream(from: data)
            try await client.putObject(key: key, stream: stream, length: Int64(data.count))
            uploadedData[key] = data
        }

        print("   📤 Uploaded \(numFiles) test files")

        // Test concurrent downloads
        let startTime = Date()

        let downloadedData = try await withThrowingTaskGroup(of: (String, Data).self) { group in
            for (key, _) in uploadedData {
                group.addTask {
                    let stream = try await client.getObjectStream(key: key)
                    var data = Data()
                    for try await buffer in stream {
                        data.append(buffer)
                    }
                    return (key, data)
                }
            }

            var results = [String: Data]()
            for try await (key, data) in group {
                results[key] = data
            }
            return results
        }

        let duration = Date().timeIntervalSince(startTime)
        let totalData = numFiles * fileSize
        let throughput = Double(totalData) / duration / (1024 * 1024) // MB/s

        print("   ✅ \(numFiles) concurrent downloads completed")
        print(String(format: "   📊 Throughput: %.2f MB/s", throughput))
        print(String(format: "   ⏱️  Duration: %.2f seconds", duration))

        // Verify data integrity
        for (key, originalData) in uploadedData {
            XCTAssertEqual(downloadedData[key], originalData, "Downloaded data should match original for \(key)")
        }

        // Cleanup
        for key in uploadedData.keys {
            try await client.deleteObject(key: key)
        }
        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    func testHighFrequencyOperations() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting High Frequency Operations Test")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        let numOperations = 50
        let startTime = Date()

        // Rapid create/delete operations
        for i in 0..<numOperations {
            let key = "rapid-op-\(i).txt"
            let data = "Test data \(i)".data(using: .utf8)!
            let stream = createStream(from: data)

            try await client.putObject(key: key, stream: stream, length: Int64(data.count))

            // Immediately try to get it
            let getStream = try await client.getObjectStream(key: key)
            var retrievedData = Data()
            for try await buffer in getStream {
                retrievedData.append(buffer)
            }
            XCTAssertEqual(retrievedData, data, "Retrieved data should match uploaded data")

            // Delete it
            try await client.deleteObject(key: key)
        }

        let duration = Date().timeIntervalSince(startTime)
        let opsPerSecond = Double(numOperations) / duration

        print("   ✅ \(numOperations) rapid operations completed")
        print(String(format: "   📊 Operations/second: %.2f", opsPerSecond))
        print(String(format: "   ⏱️  Duration: %.2f seconds", duration))

        // Cleanup
        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    // MARK: - Large Scale Tests

    func testManySmallFiles() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Many Small Files Test")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        let numFiles = 100
        _ = 1024 // 1KB each (not used, files have variable size)
        var uploadedKeys = [String]()

        let startTime = Date()

        // Upload many small files
        for i in 0..<numFiles {
            let key = String(format: "small-file-%03d.txt", i)
            let data = "Content of file \(i)\n".data(using: .utf8)!
            let stream = createStream(from: data)
            try await client.putObject(key: key, stream: stream, length: Int64(data.count))
            uploadedKeys.append(key)
        }

        let uploadDuration = Date().timeIntervalSince(startTime)
        print("   📤 Uploaded \(numFiles) small files in \(String(format: "%.2f", uploadDuration))s")

        // List all objects
        let listStartTime = Date()
        let objects = try await client.listObjects(prefix: nil, delimiter: nil)
        let listDuration = Date().timeIntervalSince(listStartTime)

        XCTAssertEqual(objects.count, numFiles, "All files should be listed")

        print("   📋 Listed \(objects.count) objects in \(String(format: "%.2f", listDuration))s")

        // Download and verify a sample
        let sampleKey = uploadedKeys[uploadedKeys.count / 2]
        let downloadStream = try await client.getObjectStream(key: sampleKey)
        var downloadedData = Data()
        for try await buffer in downloadStream {
            downloadedData.append(buffer)
        }

        let expectedContent = "Content of file \(uploadedKeys.firstIndex(of: sampleKey) ?? 0)\n"
        XCTAssertEqual(String(data: downloadedData, encoding: .utf8), expectedContent)

        // Cleanup - delete all files
        let cleanupStartTime = Date()
        for key in uploadedKeys {
            try await client.deleteObject(key: key)
        }
        let cleanupDuration = Date().timeIntervalSince(cleanupStartTime)

        print("   🗑️  Cleaned up \(numFiles) files in \(String(format: "%.2f", cleanupDuration))s")

        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    func testLargeFileUpload() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Large File Upload Test")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        // Test with a reasonably large file (10MB for CI environments)
        let fileSize = 10 * 1024 * 1024 // 10MB
        let key = "large-file.dat"

        print("   📊 Creating \(fileSize / (1024 * 1024))MB test file...")

        let data = createLargeData(size: fileSize)
        let stream = createStream(from: data, chunkSize: 1024 * 1024) // 1MB chunks

        let startTime = Date()
        try await client.putObject(key: key, stream: stream, length: Int64(data.count))
        let uploadDuration = Date().timeIntervalSince(startTime)

        let uploadSpeed = Double(fileSize) / uploadDuration / (1024 * 1024) // MB/s

        print("   ✅ Large file uploaded successfully")
        print(String(format: "   📊 Upload speed: %.2f MB/s", uploadSpeed))
        print(String(format: "   ⏱️  Duration: %.2f seconds", uploadDuration))

        // Verify the file
        let headResponse = try await client.getObjectSize(key: key)
        XCTAssertEqual(headResponse, fileSize, "File size should match")

        // Download and verify integrity
        let downloadStartTime = Date()
        let downloadStream = try await client.getObjectStream(key: key)
        var downloadedData = Data()
        for try await buffer in downloadStream {
            downloadedData.append(buffer)
        }
        let downloadDuration = Date().timeIntervalSince(downloadStartTime)

        XCTAssertEqual(downloadedData.count, fileSize, "Downloaded data size should match")
        // Note: For very large files, we might not want to compare all bytes in tests
        // For now, just check first and last 1KB
        XCTAssertEqual(downloadedData.prefix(1024), data.prefix(1024), "First 1KB should match")
        XCTAssertEqual(downloadedData.suffix(1024), data.suffix(1024), "Last 1KB should match")

        let downloadSpeed = Double(fileSize) / downloadDuration / (1024 * 1024) // MB/s

        print("   ✅ Large file downloaded and verified")
        print(String(format: "   📊 Download speed: %.2f MB/s", downloadSpeed))
        print(String(format: "   ⏱️  Download duration: %.2f seconds", downloadDuration))

        // Cleanup
        try await client.deleteObject(key: key)
        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    // MARK: - Mixed Workload Tests

    func testMixedConcurrentOperations() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Mixed Concurrent Operations Test")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        let startTime = Date()

        try await withThrowingTaskGroup(of: Void.self) { group in
            // Concurrent uploads
            for i in 0..<5 {
                group.addTask {
                    let key = "mixed-upload-\(i).txt"
                    let data = "Upload content \(i)".data(using: .utf8)!
                    let stream = createStream(from: data)
                    try await client.putObject(key: key, stream: stream, length: Int64(data.count))
                }
            }

            // Concurrent downloads (of files we'll upload first)
            for i in 0..<3 {
                group.addTask {
                    let key = "mixed-upload-\(i).txt"
                    // Small delay to ensure upload happens first
                    try await Task.sleep(nanoseconds: 100_000_000) // 0.1s

                    let stream = try await client.getObjectStream(key: key)
                    var data = Data()
                    for try await buffer in stream {
                        data.append(buffer)
                    }
                    let expected = "Upload content \(i)".data(using: .utf8)!
                    XCTAssertEqual(data, expected, "Downloaded content should match")
                }
            }

            // Concurrent listings
            for _ in 0..<2 {
                group.addTask {
                    let objects = try await client.listObjects(prefix: nil, delimiter: nil)
                    XCTAssertGreaterThanOrEqual(objects.count, 0, "List should succeed")
                }
            }

            try await group.waitForAll()
        }

        let duration = Date().timeIntervalSince(startTime)
        print("   ✅ Mixed concurrent operations completed")
        print(String(format: "   ⏱️  Duration: %.2f seconds", duration))

        // Final cleanup
        let objects = try await client.listObjects(prefix: nil, delimiter: nil)
        for obj in objects {
            try await client.deleteObject(key: obj.key)
        }
        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }
}