import AsyncHTTPClient
import NIOCore
import NIOFoundationCompat
import XCTest
import Crypto

@testable import CybS3Lib

final class StabilityTests: XCTestCase {

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
            print("⏭️  Skipping Stability Test: Environment variables not set.")
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

    func generateBucketName(prefix: String = "cybs3-stable") -> String {
        return "\(prefix)-\(UInt32.random(in: 1000...9999))-\(Int(Date().timeIntervalSince1970))"
    }

    // MARK: - Long Running Tests

    func testLongRunningContinuousOperations() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Long Running Continuous Operations Test")
        print("   Bucket: \(bucketName)")
        print("   Duration: ~2 minutes")

        try await client.createBucket(name: bucketName)

        let testDuration: TimeInterval = 120 // 2 minutes
        let startTime = Date()
        var operationCount = 0
        var successCount = 0
        var failureCount = 0

        while Date().timeIntervalSince(startTime) < testDuration {
            do {
                let key = "continuous-\(operationCount).txt"
                let data = "Operation \(operationCount) at \(Date())".data(using: .utf8)!
                let stream = createStream(from: data)

                // Upload
                try await client.putObject(key: key, stream: stream, length: Int64(data.count))

                // Verify
                let headResponse = try await client.getObjectSize(key: key)
                XCTAssertEqual(headResponse, data.count)

                // Download
                let downloadStream = try await client.getObjectStream(key: key)
                var downloadedData = Data()
                for try await buffer in downloadStream {
                    downloadedData.append(buffer)
                }
                XCTAssertEqual(downloadedData, data)

                // Delete
                try await client.deleteObject(key: key)

                successCount += 1

            } catch {
                failureCount += 1
                print("   ⚠️  Operation \(operationCount) failed: \(error)")
            }

            operationCount += 1

            // Progress update every 10 operations
            if operationCount % 10 == 0 {
                let elapsed = Date().timeIntervalSince(startTime)
                let progress = elapsed / testDuration * 100
                print(String(format: "   📊 Progress: %.1f%% (%d ops, %d success, %d fail)",
                            progress, operationCount, successCount, failureCount))
            }

            // Small delay to prevent overwhelming the service
            try await Task.sleep(nanoseconds: 500_000_000) // 0.5 seconds
        }

        let totalTime = Date().timeIntervalSince(startTime)
        let opsPerSecond = Double(operationCount) / totalTime
        let successRate = Double(successCount) / Double(operationCount) * 100

        print("   ✅ Long running test completed")
        print("   📊 Final Results:")
        print(String(format: "      Total operations: %d", operationCount))
        print(String(format: "      Successful: %d", successCount))
        print(String(format: "      Failed: %d", failureCount))
        print(String(format: "      Success rate: %.1f%%", successRate))
        print(String(format: "      Operations/second: %.2f", opsPerSecond))
        print(String(format: "      Duration: %.1f seconds", totalTime))

        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    func testStabilityWithIntermittentOperations() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Stability Test with Intermittent Operations")
        print("   Bucket: \(bucketName)")
        print("   Duration: ~3 minutes")

        try await client.createBucket(name: bucketName)

        let testDuration: TimeInterval = 180 // 3 minutes
        let startTime = Date()
        var cycleCount = 0

        while Date().timeIntervalSince(startTime) < testDuration {
            cycleCount += 1
            print("   🔄 Cycle \(cycleCount) starting...")

            do {
                // Phase 1: Create a batch of files
                let batchSize = 5
                var batchKeys = [String]()

                for i in 0..<batchSize {
                    let key = "stable-batch\(cycleCount)-file\(i).txt"
                    let data = "Cycle \(cycleCount), File \(i), Time: \(Date())".data(using: .utf8)!
                    let stream = createStream(from: data)
                    try await client.putObject(key: key, stream: stream, length: Int64(data.count))
                    batchKeys.append(key)
                }

                print("      📤 Created \(batchSize) files")

                // Phase 2: List and verify
                let objects = try await client.listObjects(prefix: nil, delimiter: nil)
                XCTAssertGreaterThanOrEqual(objects.count, batchKeys.count)

                print("      📋 Listed \(objects.count) total objects")

                // Phase 3: Download and verify a random file
                if let randomKey = batchKeys.randomElement() {
                    let downloadStream = try await client.getObjectStream(key: randomKey)
                    var downloadedData = Data()
                    for try await buffer in downloadStream {
                        downloadedData.append(buffer)
                    }
                    XCTAssertGreaterThan(downloadedData.count, 0)
                }

                print("      📥 Verified download")

                // Phase 4: Clean up old files (keep only recent ones)
                if cycleCount > 3 {
                    let oldPrefix = "stable-batch\(cycleCount - 3)"
                    let oldObjects = objects.filter { $0.key.hasPrefix(oldPrefix) }
                    for obj in oldObjects {
                        try await client.deleteObject(key: obj.key)
                    }
                    print("      🗑️  Cleaned up \(oldObjects.count) old files")
                }

                print("      ✅ Cycle \(cycleCount) completed successfully")

            } catch {
                print("      ❌ Cycle \(cycleCount) failed: \(error)")
                // Continue to next cycle
            }

            // Wait between cycles
            let cycleDelay: TimeInterval = 10 // 10 seconds
            print(String(format: "      ⏱️  Waiting %.0f seconds...", cycleDelay))
            try await Task.sleep(nanoseconds: UInt64(cycleDelay * 1_000_000_000))
        }

        let totalTime = Date().timeIntervalSince(startTime)
        print("   ✅ Stability test completed")
        print(String(format: "   📊 Completed %d cycles in %.1f seconds", cycleCount, totalTime))

        // Final cleanup
        let objects = try await client.listObjects(prefix: nil, delimiter: nil)
        for obj in objects {
            try await client.deleteObject(key: obj.key)
        }

        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    // MARK: - Memory Leak Detection Tests

    func testMemoryStabilityWithRepeatedOperations() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Memory Stability Test")
        print("   Bucket: \(bucketName)")
        print("   Operations: 100 iterations")

        try await client.createBucket(name: bucketName)

        let numIterations = 100
        let fileSize = 512 * 1024 // 512KB

        for i in 0..<numIterations {
            let key = "memory-test-\(i % 10).dat" // Reuse 10 keys to test overwrites
            let data = createTestData(size: fileSize)
            let stream = createStream(from: data)

            // Upload
            try await client.putObject(key: key, stream: stream, length: Int64(data.count))

            // Download
            let downloadStream = try await client.getObjectStream(key: key)
            var downloadedData = Data()
            for try await buffer in downloadStream {
                downloadedData.append(buffer)
            }

            XCTAssertEqual(downloadedData.count, fileSize)

            // Progress update
            if (i + 1) % 20 == 0 {
                print("   📊 Completed \(i + 1)/\(numIterations) iterations")
            }
        }

        print("   ✅ Memory stability test completed")

        // Cleanup
        let objects = try await client.listObjects(prefix: nil, delimiter: nil)
        for obj in objects {
            try await client.deleteObject(key: obj.key)
        }

        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    // MARK: - Connection Stability Tests

    func testConnectionStability() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()

        print("🧪 Starting Connection Stability Test")
        print("   Bucket: \(bucketName)")
        print("   Testing client recreation and connection reuse")

        // Test 1: Create and destroy multiple clients
        for i in 0..<5 {
            let client = createClient(creds: creds, bucket: bucketName)

            if i == 0 {
                try await client.createBucket(name: bucketName)
            }

            // Perform some operations
            let key = "connection-test-\(i).txt"
            let data = "Connection test \(i)".data(using: .utf8)!
            let stream = createStream(from: data)

            try await client.putObject(key: key, stream: stream, length: Int64(data.count))

            let headResponse = try await client.getObjectSize(key: key)
            XCTAssertEqual(headResponse, data.count)

            try await client.deleteObject(key: key)

            // Always shutdown client
            try await client.shutdown()

            print("   ✅ Client \(i) lifecycle completed")
        }

        // Test 2: Long-lived client with many operations
        let longLivedClient = createClient(creds: creds, bucket: bucketName)

        let numOperations = 50
        for i in 0..<numOperations {
            let key = "long-lived-\(i).txt"
            let data = "Long lived test \(i)".data(using: .utf8)!
            let stream = createStream(from: data)

            try await longLivedClient.putObject(key: key, stream: stream, length: Int64(data.count))

            if i % 10 == 0 {
                print("   📊 Long-lived client: \(i)/\(numOperations) operations")
            }
        }

        // List all objects
        let objects = try await longLivedClient.listObjects(prefix: nil, delimiter: nil)
        XCTAssertEqual(objects.count, numOperations)

        // Clean up all objects
        for obj in objects {
            try await longLivedClient.deleteObject(key: obj.key)
        }

        try await longLivedClient.deleteBucket(name: bucketName)
        try await longLivedClient.shutdown()

        print("   ✅ Connection stability test completed")
    }

    // MARK: - Recovery and Resilience Tests

    func testRecoveryFromTransientFailures() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        let bucketName = generateBucketName()
        let client = createClient(creds: creds, bucket: bucketName)

        print("🧪 Starting Recovery from Transient Failures Test")
        print("   Bucket: \(bucketName)")

        try await client.createBucket(name: bucketName)

        let numTestOperations = 20
        var successfulOperations = 0
        var retriedOperations = 0

        for i in 0..<numTestOperations {
            let key = "recovery-test-\(i).txt"
            let data = "Recovery test data \(i)".data(using: .utf8)!

            var attempt = 0
            let maxAttempts = 3

            while attempt < maxAttempts {
                do {
                    let stream = createStream(from: data)
                    try await client.putObject(key: key, stream: stream, length: Int64(data.count))

                    // Verify
                    let headResponse = try await client.getObjectSize(key: key)
                    XCTAssertEqual(headResponse, data.count)

                    successfulOperations += 1
                    if attempt > 0 {
                        retriedOperations += 1
                    }
                    break

                } catch {
                    attempt += 1
                    if attempt < maxAttempts {
                        print("   ⚠️  Operation \(i) attempt \(attempt) failed: \(error)")
                        print("      Retrying...")
                        // Wait before retry
                        try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
                    } else {
                        print("   ❌ Operation \(i) failed after \(maxAttempts) attempts")
                    }
                }
            }

            // Clean up successful operations
            if attempt < maxAttempts {
                try await client.deleteObject(key: key)
            }
        }

        let successRate = Double(successfulOperations) / Double(numTestOperations) * 100

        print("   ✅ Recovery test completed")
        print("   📊 Results:")
        print(String(format: "      Total operations: %d", numTestOperations))
        print(String(format: "      Successful: %d", successfulOperations))
        print(String(format: "      Required retry: %d", retriedOperations))
        print(String(format: "      Success rate: %.1f%%", successRate))

        try await client.deleteBucket(name: bucketName)
        try await client.shutdown()
    }

    // MARK: - Resource Cleanup Tests

    func testResourceCleanupUnderStress() async throws {
        guard let creds = skipIfNoCredentials() else { return }

        print("🧪 Starting Resource Cleanup Under Stress Test")

        // Create multiple buckets and clients to test cleanup
        let numBuckets = 3
        var clients = [S3Client]()
        var bucketNames = [String]()

        for i in 0..<numBuckets {
            let bucketName = generateBucketName(prefix: "cleanup-stress-\(i)")
            bucketNames.append(bucketName)

            let client = createClient(creds: creds, bucket: bucketName)
            clients.append(client)

            try await client.createBucket(name: bucketName)

            // Add some files to each bucket
            for j in 0..<5 {
                let key = "cleanup-file-\(j).txt"
                let data = "Cleanup test bucket \(i) file \(j)".data(using: .utf8)!
                let stream = createStream(from: data)
                try await client.putObject(key: key, stream: stream, length: Int64(data.count))
            }

            print("   📤 Created bucket \(bucketName) with 5 files")
        }

        // Simulate stress by performing operations across all buckets
        try await withThrowingTaskGroup(of: Void.self) { group in
            for (_, client) in clients.enumerated() {
                group.addTask {
                    // List objects
                    let objects = try await client.listObjects(prefix: nil, delimiter: nil)
                    XCTAssertEqual(objects.count, 5)

                    // Download and verify one file
                    if let firstObj = objects.first {
                        let downloadStream = try await client.getObjectStream(key: firstObj.key)
                        var data = Data()
                        for try await buffer in downloadStream {
                            data.append(buffer)
                        }
                        XCTAssertGreaterThan(data.count, 0)
                    }
                }
            }
            try await group.waitForAll()
        }

        print("   ✅ Stress operations completed")

        // Clean up everything
        for (index, client) in clients.enumerated() {
            let bucketName = bucketNames[index]

            // Delete all objects
            let objects = try await client.listObjects(prefix: nil, delimiter: nil)
            for obj in objects {
                try await client.deleteObject(key: obj.key)
            }

            // Delete bucket
            try await client.deleteBucket(name: bucketName)

            // Shutdown client
            try await client.shutdown()

            print("   🗑️  Cleaned up bucket \(bucketName)")
        }

        print("   ✅ Resource cleanup test completed")
    }
}