import AsyncHTTPClient
import NIOCore
import NIOFoundationCompat
import XCTest
import Crypto

@testable import CybS3Lib

final class StressTests: XCTestCase {

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
            print("⏭️  Skipping Stress Test: Environment variables not set.")
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

    func generateBucketName(prefix: String = "cybs3-stress") -> String {
        return "\(prefix)-\(UInt32.random(in: 1000...9999))-\(Int(Date().timeIntervalSince1970))"
    }

    // MARK: - Memory Stress Tests

    func testMemoryStressWithLargeFiles() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Memory Stress Test with Large Files")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        // Test with multiple large files to stress memory
        let fileSizes = [5 * 1024 * 1024, 10 * 1024 * 1024, 15 * 1024 * 1024] // 5MB, 10MB, 15MB
        var uploadedFiles = [(key: String, size: Int)]()

        for (index, fileSize) in fileSizes.enumerated() {
            let key = "memory-stress-\(index).dat"
            print("   📊 Creating \(fileSize / (1024 * 1024))MB file...")

            let data = createRandomData(size: fileSize)
            let stream = createStream(from: data, chunkSize: 512 * 1024) // Smaller chunks to test streaming

            let startTime = Date()
            try await client.putObject(key: key, stream: stream, length: Int64(data.count))
            let duration = Date().timeIntervalSince(startTime)

            print(String(format: "   ✅ Uploaded \(fileSize / (1024 * 1024))MB in %.2f seconds", duration))
            uploadedFiles.append((key, fileSize))
        }

        // Download and verify (this will stress memory differently)
        for (key, expectedSize) in uploadedFiles {
            print("   📥 Downloading and verifying \(key)...")

            let downloadStream = try await client.getObjectStream(key: key)
            var downloadedData = Data()
            var totalBytes = 0

            for try await buffer in downloadStream {
                downloadedData.append(buffer)
                totalBytes += buffer.count

                // Simulate processing that might accumulate memory
                if downloadedData.count > 1024 * 1024 { // Keep only last 1MB in memory
                    downloadedData.removeFirst(downloadedData.count - 1024 * 1024)
                }
            }

            XCTAssertEqual(totalBytes, expectedSize, "Downloaded size should match for \(key)")
            print("   ✅ Verified \(key) - \(totalBytes) bytes")
        }

        // Cleanup
        for (key, _) in uploadedFiles {
            try await client.deleteObject(key: key)
        }
        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    func testConcurrentMemoryStress() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Concurrent Memory Stress Test")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        let numConcurrent = 3
        let fileSize = 8 * 1024 * 1024 // 8MB each

        // Pre-create data and streams to avoid capturing self in closures
        let testData = (0..<numConcurrent).map { _ in createRandomData(size: fileSize) }
        let testStreams = testData.map { createStream(from: $0) }

        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<numConcurrent {
                let data = testData[i]
                let stream = testStreams[i]
                group.addTask {
                    let key = "concurrent-memory-\(i).dat"

                    // Upload
                    try await client.putObject(key: key, stream: stream, length: Int64(data.count))

                    // Immediately download to stress memory with concurrent operations
                    let downloadStream = try await client.getObjectStream(key: key)
                    var downloadedData = Data()
                    for try await buffer in downloadStream {
                        downloadedData.append(buffer)
                    }

                    XCTAssertEqual(downloadedData.count, fileSize, "Downloaded data size should match")

                    // Clean up this file
                    try await client.deleteObject(key: key)
                }
            }
            try await group.waitForAll()
        }

        print("   ✅ Concurrent memory stress test completed")

        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    // MARK: - Network Stress Tests

    func testNetworkStressWithRetries() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Network Stress Test with Retries")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        let numOperations = 20
        var successCount = 0
        var failureCount = 0

        // Perform many operations that might encounter network issues
        for i in 0..<numOperations {
            let key = "network-stress-\(i).txt"
            let data = "Network stress test data \(i)".data(using: .utf8)!

            do {
                let stream = createStream(from: data)
                try await client.putObject(key: key, stream: stream, length: Int64(data.count))

                // Verify it exists
                let headResponse = try await client.getObjectSize(key: key)
                XCTAssertEqual(headResponse, data.count)

                successCount += 1

                // Clean up
                try await client.deleteObject(key: key)
            } catch {
                failureCount += 1
                print("   ⚠️  Operation \(i) failed: \(error)")
            }
        }

        print("   📊 Network stress results: \(successCount) successes, \(failureCount) failures")

        // We expect most operations to succeed
        XCTAssertGreaterThan(successCount, numOperations / 2, "At least half of network operations should succeed")

        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    func testConnectionPoolingStress() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()

        print("🧪 Starting Connection Pooling Stress Test")
        print("   Bucket: \(bucketName)")

        // Create multiple clients to stress connection pooling
        let numClients = 5
        var clients = [S3Client]()

        for i in 0..<numClients {
            let client = createClient(creds: creds, bucket: bucketName)
            clients.append(client)

            if i == 0 { // Only one client needs to create the bucket
                try await client.createBucket(name: bucketName)
            }
        }

        let numOperationsPerClient = 10

        try await withThrowingTaskGroup(of: Void.self) { group in
            for (clientIndex, client) in clients.enumerated() {
                group.addTask {
                    for opIndex in 0..<numOperationsPerClient {
                        let key = "pool-stress-c\(clientIndex)-op\(opIndex).txt"
                        let data = "Data from client \(clientIndex), operation \(opIndex)".data(using: .utf8)!
                        let stream = createStream(from: data)

                        try await client.putObject(key: key, stream: stream, length: Int64(data.count))

                        // Quick verification
                        let headResponse = try await client.getObjectSize(key: key)
                        XCTAssertEqual(headResponse, data.count)
                    }
                }
            }
            try await group.waitForAll()
        }

        print("   ✅ Connection pooling stress test completed")

        // Cleanup - use first client
        let objects = try await clients[0].listObjects(prefix: nil, delimiter: nil)
        for obj in objects {
            try await clients[0].deleteObject(key: obj.key)
        }
        try await clients[0].deleteBucket(name: bucketName)

        // Shutdown all clients
        for client in clients {
            try await client.shutdown()
        }
    }

    // MARK: - Edge Case Stress Tests

    func testEdgeCaseFileNames() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Edge Case File Names Stress Test")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        let edgeCaseNames = [
            "file with spaces.txt",
            "file-with-dashes.txt",
            "file_with_underscores.txt",
            "file.with.dots.txt",
            "file-with-unicode-🚀.txt",
            "file-with-very-long-name-that-might-cause-issues-with-some-s3-implementations-because-it-exceeds-normal-limits.txt",
            "file/with/slashes.txt", // This might be treated as a folder structure
            "file%20with%20encoding.txt",
            "file+with+plus.txt",
            "..",
            ".",
            "",
            "normal-file.txt"
        ]

        var successfulUploads = 0

        for name in edgeCaseNames {
            do {
                let data = "Content of \(name)".data(using: .utf8)!
                let stream = createStream(from: data)

                try await client.putObject(key: name, stream: stream, length: Int64(data.count))
                successfulUploads += 1

                // Try to retrieve it
                let headResponse = try await client.getObjectSize(key: name)
                XCTAssertEqual(headResponse, data.count)

                // Clean up
                try await client.deleteObject(key: name)
            } catch {
                print("   ⚠️  Failed to handle filename '\(name)': \(error)")
            }
        }

        print("   ✅ Successfully handled \(successfulUploads)/\(edgeCaseNames.count) edge case filenames")

        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    func testEmptyAndBoundaryFiles() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Empty and Boundary Files Stress Test")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        let testCases = [
            ("empty-file", Data()),
            ("single-byte", Data([0x42])),
            ("exact-1kb", createRandomData(size: 1024)),
            ("exact-1mb", createRandomData(size: 1024 * 1024)),
            ("boundary-1023b", createRandomData(size: 1023)),
            ("boundary-1025b", createRandomData(size: 1025)),
            ("unicode-content", "🚀 Hello 🌍 World 🌟".data(using: .utf8)!)
        ]

        for (key, data) in testCases {
            print("   📤 Testing \(key) - \(data.count) bytes")

            let stream = createStream(from: data)
            try await client.putObject(key: key, stream: stream, length: Int64(data.count))

            // Verify
            let headResponse = try await client.getObjectSize(key: key)
            XCTAssertEqual(headResponse, data.count)

            // Download and verify
            let downloadStream = try await client.getObjectStream(key: key)
            var downloadedData = Data()
            for try await buffer in downloadStream {
                downloadedData.append(buffer)
            }

            XCTAssertEqual(downloadedData, data, "Data should match for \(key)")

            // Clean up
            try await client.deleteObject(key: key)
        }

        print("   ✅ All boundary and empty file tests passed")

        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    // MARK: - Error Recovery Stress Tests

    func testErrorRecoveryStress() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Error Recovery Stress Test")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        // Test operations on non-existent objects
        let nonExistentKeys = ["does-not-exist-1.txt", "does-not-exist-2.txt", "missing-file.dat"]

        for key in nonExistentKeys {
            do {
                _ = try await client.getObjectStream(key: key)
                XCTFail("Should have failed to get non-existent object: \(key)")
            } catch {
                // Expected to fail
                print("   ✅ Correctly failed to get non-existent object: \(key)")
            }

            do {
                _ = try await client.getObjectSize(key: key)
                XCTFail("Should have failed to head non-existent object: \(key)")
            } catch {
                // Expected to fail
                print("   ✅ Correctly failed to head non-existent object: \(key)")
            }

            do {
                try await client.deleteObject(key: key)
                // Delete on non-existent object might succeed or fail depending on S3 implementation
                print("   ℹ️  Delete on non-existent object: \(key) - may succeed or fail")
            } catch {
                print("   ✅ Correctly failed to delete non-existent object: \(key)")
            }
        }

        // Test operations on non-existent bucket
        let nonExistentBucket = "this-bucket-does-not-exist-12345"
        let tempClient = createClient(creds: creds, bucket: nonExistentBucket)

        do {
            _ = try await tempClient.listObjects(prefix: nil, delimiter: nil)
            XCTFail("Should have failed to list objects in non-existent bucket")
        } catch {
            print("   ✅ Correctly failed to list objects in non-existent bucket")
        }

        try await tempClient.shutdown()

        print("   ✅ Error recovery stress test completed")

        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }
}