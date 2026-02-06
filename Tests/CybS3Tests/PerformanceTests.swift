import AsyncHTTPClient
import NIOCore
import NIOFoundationCompat
import XCTest
import Crypto

@testable import CybS3Lib

final class PerformanceTests: XCTestCase {

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
            print("⏭️  Skipping Performance Test: Environment variables not set.")
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

    func generateBucketName(prefix: String = "cybs3-perf") -> String {
        return "\(prefix)-\(UInt32.random(in: 1000...9999))-\(Int(Date().timeIntervalSince1970))"
    }

    // MARK: - Upload Performance Tests

    func testUploadPerformanceSmallFiles() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Upload Performance Test - Small Files")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        let numFiles = 50
        let fileSize = 64 * 1024 // 64KB each
        var uploadedKeys = [String]()

        let data = createTestData(size: fileSize)

        // Warm up
        let warmupKey = "warmup.txt"
        let warmupStream = createStream(from: data)
        try await client.putObject(key: warmupKey, stream: warmupStream, length: Int64(data.count))
        try await client.deleteObject(key: warmupKey)

        // Performance test
        let startTime = Date()

        for i in 0..<numFiles {
            let key = String(format: "perf-small-%03d.dat", i)
            let stream = createStream(from: data)
            try await client.putObject(key: key, stream: stream, length: Int64(data.count))
            uploadedKeys.append(key)
        }

        let duration = Date().timeIntervalSince(startTime)
        let totalData = numFiles * fileSize
        let throughput = Double(totalData) / duration / (1024 * 1024) // MB/s
        let avgFileTime = duration / Double(numFiles) * 1000 // ms per file

        print("   📊 Upload Performance Results:")
        print(String(format: "      Files: %d × %d KB", numFiles, fileSize / 1024))
        print(String(format: "      Total: %.2f MB", Double(totalData) / (1024 * 1024)))
        print(String(format: "      Time: %.2f seconds", duration))
        print(String(format: "      Throughput: %.2f MB/s", throughput))
        print(String(format: "      Avg per file: %.2f ms", avgFileTime))

        // Cleanup
        for key in uploadedKeys {
            try await client.deleteObject(key: key)
        }
        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    func testUploadPerformanceLargeFile() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Upload Performance Test - Large File")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        let fileSize = 20 * 1024 * 1024 // 20MB
        let key = "perf-large.dat"

        let data = createTestData(size: fileSize)
        let stream = createStream(from: data, chunkSize: 1024 * 1024) // 1MB chunks

        // Warm up with small file
        let warmupData = createTestData(size: 1024)
        let warmupStream = createStream(from: warmupData)
        try await client.putObject(key: "warmup.txt", stream: warmupStream, length: Int64(warmupData.count))
        try await client.deleteObject(key: "warmup.txt")

        // Performance test
        let startTime = Date()
        try await client.putObject(key: key, stream: stream, length: Int64(data.count))
        let duration = Date().timeIntervalSince(startTime)

        let throughput = Double(fileSize) / duration / (1024 * 1024) // MB/s

        print("   📊 Large File Upload Performance:")
        print(String(format: "      Size: %.2f MB", Double(fileSize) / (1024 * 1024)))
        print(String(format: "      Time: %.2f seconds", duration))
        print(String(format: "      Throughput: %.2f MB/s", throughput))

        // Verify
        let headResponse = try await client.getObjectSize(key: key)
        XCTAssertEqual(headResponse, fileSize)

        // Cleanup
        try await client.deleteObject(key: key)
        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    // MARK: - Download Performance Tests

    func testDownloadPerformanceSmallFiles() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Download Performance Test - Small Files")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        let numFiles = 50
        let fileSize = 64 * 1024 // 64KB each
        var uploadedKeys = [String]()

        // Upload test files
        let data = createTestData(size: fileSize)
        for i in 0..<numFiles {
            let key = String(format: "perf-download-small-%03d.dat", i)
            let stream = createStream(from: data)
            try await client.putObject(key: key, stream: stream, length: Int64(data.count))
            uploadedKeys.append(key)
        }

        print("   📤 Uploaded \(numFiles) test files")

        // Performance test
        let startTime = Date()
        var totalDownloadedBytes = 0

        for key in uploadedKeys {
            let downloadStream = try await client.getObjectStream(key: key)
            var fileData = Data()
            for try await buffer in downloadStream {
                fileData.append(buffer)
            }
            totalDownloadedBytes += fileData.count
            XCTAssertEqual(fileData.count, fileSize)
        }

        let duration = Date().timeIntervalSince(startTime)
        let throughput = Double(totalDownloadedBytes) / duration / (1024 * 1024) // MB/s
        let avgFileTime = duration / Double(numFiles) * 1000 // ms per file

        print("   📊 Download Performance Results:")
        print(String(format: "      Files: %d × %d KB", numFiles, fileSize / 1024))
        print(String(format: "      Total: %.2f MB", Double(totalDownloadedBytes) / (1024 * 1024)))
        print(String(format: "      Time: %.2f seconds", duration))
        print(String(format: "      Throughput: %.2f MB/s", throughput))
        print(String(format: "      Avg per file: %.2f ms", avgFileTime))

        // Cleanup
        for key in uploadedKeys {
            try await client.deleteObject(key: key)
        }
        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    func testDownloadPerformanceLargeFile() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Download Performance Test - Large File")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        let fileSize = 20 * 1024 * 1024 // 20MB
        let key = "perf-download-large.dat"

        // Upload test file
        let data = createTestData(size: fileSize)
        let uploadStream = createStream(from: data, chunkSize: 1024 * 1024)
        try await client.putObject(key: key, stream: uploadStream, length: Int64(data.count))

        print("   📤 Uploaded test file")

        // Performance test
        let startTime = Date()
        let downloadStream = try await client.getObjectStream(key: key)
        var downloadedData = Data()
        for try await buffer in downloadStream {
            downloadedData.append(buffer)
        }
        let duration = Date().timeIntervalSince(startTime)

        let throughput = Double(downloadedData.count) / duration / (1024 * 1024) // MB/s

        print("   📊 Large File Download Performance:")
        print(String(format: "      Size: %.2f MB", Double(downloadedData.count) / (1024 * 1024)))
        print(String(format: "      Time: %.2f seconds", duration))
        print(String(format: "      Throughput: %.2f MB/s", throughput))

        XCTAssertEqual(downloadedData.count, fileSize)

        // Cleanup
        try await client.deleteObject(key: key)
        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    // MARK: - List Performance Tests

    func testListPerformance() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting List Performance Test")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        let numFiles = 200
        var uploadedKeys = [String]()

        // Create test files
        let data = createTestData(size: 1024) // 1KB each
        for i in 0..<numFiles {
            let key = String(format: "perf-list-%04d.txt", i)
            let stream = createStream(from: data)
            try await client.putObject(key: key, stream: stream, length: Int64(data.count))
            uploadedKeys.append(key)
        }

        print("   📤 Created \(numFiles) test files")

        // Performance test - multiple list operations
        let numListOperations = 10
        var totalListTime = 0.0
        var totalObjectsFound = 0

        for _ in 0..<numListOperations {
            let listStartTime = Date()
            let objects = try await client.listObjects(prefix: nil, delimiter: nil)
            let listDuration = Date().timeIntervalSince(listStartTime)

            totalListTime += listDuration
            totalObjectsFound += objects.count
        }

        let avgListTime = totalListTime / Double(numListOperations)
        let objectsPerSecond = Double(totalObjectsFound) / totalListTime

        print("   📊 List Performance Results:")
        print(String(format: "      Operations: %d", numListOperations))
        print(String(format: "      Total objects found: %d", totalObjectsFound))
        print(String(format: "      Avg time per list: %.3f seconds", avgListTime))
        print(String(format: "      Objects/second: %.1f", objectsPerSecond))

        // Cleanup
        for key in uploadedKeys {
            try await client.deleteObject(key: key)
        }
        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    // MARK: - Memory Usage Tests

    func testMemoryUsageDuringOperations() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Memory Usage Test")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        // Test memory usage with multiple concurrent operations
        let numConcurrent = 5
        let fileSize = 2 * 1024 * 1024 // 2MB each

        let startTime = Date()

        // Pre-create data to avoid capturing self in closures
        let testData = (0..<numConcurrent).map { _ in createTestData(size: fileSize) }

        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<numConcurrent {
                let data = testData[i]
                let stream = createStream(from: data)
                group.addTask {
                    let key = "memory-test-\(i).dat"

                    // Upload
                    try await client.putObject(key: key, stream: stream, length: Int64(data.count))

                    // Download immediately (this should not accumulate memory)
                    let downloadStream = try await client.getObjectStream(key: key)
                    var downloadedData = Data()
                    for try await buffer in downloadStream {
                        downloadedData.append(buffer)
                        // Simulate processing that releases memory immediately
                        if downloadedData.count > 1024 * 1024 {
                            downloadedData.removeAll(keepingCapacity: false)
                        }
                    }

                    // Clean up
                    try await client.deleteObject(key: key)
                }
            }
            try await group.waitForAll()
        }

        let duration = Date().timeIntervalSince(startTime)
        print("   ✅ Memory usage test completed")
        print(String(format: "   ⏱️  Duration: %.2f seconds", duration))

        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    // MARK: - Round Trip Performance Tests

    func testRoundTripPerformance() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Round Trip Performance Test")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        let testSizes = [1024, 64 * 1024, 1024 * 1024, 5 * 1024 * 1024] // 1KB, 64KB, 1MB, 5MB
        let numRoundsPerSize = 3

        for fileSize in testSizes {
            print("   📊 Testing \(fileSize / 1024)KB files...")

            var totalUploadTime = 0.0
            var totalDownloadTime = 0.0
            var totalDataTransferred = 0

            for round in 0..<numRoundsPerSize {
                let key = "roundtrip-\(fileSize)-\(round).dat"
                let data = createTestData(size: fileSize)

                // Upload
                let uploadStart = Date()
                let uploadStream = createStream(from: data)
                try await client.putObject(key: key, stream: uploadStream, length: Int64(data.count))
                let uploadTime = Date().timeIntervalSince(uploadStart)
                totalUploadTime += uploadTime

                // Download
                let downloadStart = Date()
                let downloadStream = try await client.getObjectStream(key: key)
                var downloadedData = Data()
                for try await buffer in downloadStream {
                    downloadedData.append(buffer)
                }
                let downloadTime = Date().timeIntervalSince(downloadStart)
                totalDownloadTime += downloadTime

                totalDataTransferred += downloadedData.count

                // Verify
                XCTAssertEqual(downloadedData, data)

                // Clean up
                try await client.deleteObject(key: key)
            }

            let avgUploadTime = totalUploadTime / Double(numRoundsPerSize)
            let avgDownloadTime = totalDownloadTime / Double(numRoundsPerSize)
            let totalRoundTripTime = avgUploadTime + avgDownloadTime

            let uploadThroughput = Double(fileSize) / avgUploadTime / (1024 * 1024) // MB/s
            let downloadThroughput = Double(fileSize) / avgDownloadTime / (1024 * 1024) // MB/s

            print(String(format: "      Size: %d KB", fileSize / 1024))
            print(String(format: "      Upload: %.3fs (%.2f MB/s)", avgUploadTime, uploadThroughput))
            print(String(format: "      Download: %.3fs (%.2f MB/s)", avgDownloadTime, downloadThroughput))
            print(String(format: "      Round trip: %.3fs", totalRoundTripTime))
        }

        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }
}