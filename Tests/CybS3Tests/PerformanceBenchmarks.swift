import XCTest
import CybS3Lib

/// Performance benchmarks to measure actual performance improvements.
final class PerformanceBenchmarks: XCTestCase {
    // Test credentials
    private let testEndpoint = "s3.eu-west-4.idrivee2.com"
    private let testRegion = "eu-west-4"
    private let testAccessKey = "E9GDPm2f9bZrUYVBINXn"
    private let testSecretKey = "RMJuDc0hjrfZLr2aOYlVq3be7mQnzHTP7DVUngnR"
    private let testBucket = "cybs3-performance-test-\(UUID().uuidString.prefix(8))"

    private var s3Client: S3Client!

    override func setUp() async throws {
        try await super.setUp()

        let endpoint = S3Endpoint(host: testEndpoint, port: 443, useSSL: true)
        s3Client = S3Client(
            endpoint: endpoint,
            accessKey: testAccessKey,
            secretKey: testSecretKey,
            bucket: testBucket,
            region: testRegion
        )

        // Create test bucket
        try await s3Client.createBucketIfNotExists()
    }

    override func tearDown() async throws {
        // Clean up test objects
        do {
            let objects = try await s3Client.listObjects(maxKeys: 100)
            for object in objects where object.key.hasPrefix("bench-") {
                try await s3Client.deleteObject(key: object.key)
            }
        } catch {
            print("Warning: Failed to clean up benchmark objects: \(error)")
        }

        try await super.tearDown()
    }

    /// Benchmark single object operations.
    func testSingleObjectBenchmark() async throws {
        let testData = Data(repeating: 0x41, count: 1024 * 1024) // 1MB
        let key = "bench-single-\(UUID().uuidString)"

        // Measure upload time
        let uploadTime = try await measureTime {
            try await s3Client.putObject(key: key, data: testData)
        }

        // Measure download time
        let downloadTime = try await measureTime {
            _ = try await s3Client.getObject(key: key)
        }

        // Measure list time
        let listTime = try await measureTime {
            _ = try await s3Client.listObjects(maxKeys: 10)
        }

        print("Single Object Benchmark Results:")
        print("  Upload (1MB): \(String(format: "%.3f", uploadTime))s (\(String(format: "%.2f", Double(testData.count) / uploadTime / 1024 / 1024)) MB/s)")
        print("  Download (1MB): \(String(format: "%.3f", downloadTime))s (\(String(format: "%.2f", Double(testData.count) / downloadTime / 1024 / 1024)) MB/s)")
        print("  List (10 items): \(String(format: "%.3f", listTime))s")

        // Clean up
        try await s3Client.deleteObject(key: key)
    }

    /// Benchmark concurrent operations.
    func testConcurrentOperationsBenchmark() async throws {
        let objectCount = 20
        let objectSize = 512 * 1024 // 512KB per object
        let testData = Data(repeating: 0x42, count: objectSize)

        // Upload objects concurrently
        let uploadTime = try await measureTime {
            try await withThrowingTaskGroup(of: Void.self) { group in
                for i in 0..<objectCount {
                    group.addTask { [client = s3Client!] in
                        let key = "bench-concurrent-\(i)-\(UUID().uuidString)"
                        try await client.putObject(key: key, data: testData)
                    }
                }
                try await group.waitForAll()
            }
        }

        // Download objects concurrently
        let downloadTime = try await measureTime {
            try await withThrowingTaskGroup(of: Void.self) { group in
                for i in 0..<objectCount {
                    group.addTask { [client = s3Client!] in
                        let key = "bench-concurrent-\(i)-\(UUID().uuidString)"
                        _ = try await client.getObject(key: key)
                    }
                }
                try await group.waitForAll()
            }
        }

        let totalDataTransferred = Double(objectCount * objectSize)

        print("Concurrent Operations Benchmark (\(objectCount) objects × \(objectSize / 1024)KB):")
        print("  Concurrent Upload: \(String(format: "%.3f", uploadTime))s (\(String(format: "%.2f", totalDataTransferred / uploadTime / 1024 / 1024)) MB/s)")
        print("  Concurrent Download: \(String(format: "%.3f", downloadTime))s (\(String(format: "%.2f", totalDataTransferred / downloadTime / 1024 / 1024)) MB/s)")
        print("  Objects per second: Upload: \(String(format: "%.1f", Double(objectCount) / uploadTime)), Download: \(String(format: "%.1f", Double(objectCount) / downloadTime))")

        // Clean up
        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<objectCount {
                group.addTask { [client = s3Client!] in
                    let key = "bench-concurrent-\(i)-\(UUID().uuidString)"
                    try await client.deleteObject(key: key)
                }
            }
            try await group.waitForAll()
        }
    }

    /// Benchmark large file operations.
    func testLargeFileBenchmark() async throws {
        let sizes = [5 * 1024 * 1024, 10 * 1024 * 1024, 25 * 1024 * 1024] // 5MB, 10MB, 25MB

        for size in sizes {
            let testData = Data(repeating: 0x43, count: size)
            let key = "bench-large-\(size / (1024 * 1024))MB-\(UUID().uuidString)"

            // Upload
            let uploadTime = try await measureTime {
                try await self.s3Client.putObjectMultipart(key: key, data: testData, partSize: 5 * 1024 * 1024)
            }

            // Download
            let downloadTime = try await measureTime {
                _ = try await self.s3Client.getObject(key: key)
            }

            let sizeMB = Double(size) / 1024 / 1024
            print("Large File Benchmark (\(String(format: "%.0f", sizeMB))MB):")
            print("  Upload: \(String(format: "%.3f", uploadTime))s (\(String(format: "%.2f", sizeMB / uploadTime)) MB/s)")
            print("  Download: \(String(format: "%.3f", downloadTime))s (\(String(format: "%.2f", sizeMB / downloadTime)) MB/s)")

            // Clean up
            try await s3Client.deleteObject(key: key)
        }
    }

    /// Benchmark encryption performance.
    func testEncryptionPerformance() throws {
        let sizes = [1024, 1024 * 1024, 10 * 1024 * 1024] // 1KB, 1MB, 10MB
        let mnemonic = ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                       "abandon", "abandon", "abandon", "abandon", "abandon", "about"]

        let key = try Encryption.deriveKey(mnemonic: mnemonic)

        for size in sizes {
            let testData = Data(repeating: 0x44, count: size)

            // Measure encryption
            let encryptTime = try measureTime {
                _ = try Encryption.encrypt(data: testData, key: key)
            }

            // Measure decryption
            let encrypted = try Encryption.encrypt(data: testData, key: key)
            let decryptTime = try measureTime {
                _ = try Encryption.decrypt(data: encrypted, key: key)
            }

            let sizeKB = Double(size) / 1024
            print("Encryption Performance (\(String(format: "%.0f", sizeKB))KB):")
            print("  Encrypt: \(String(format: "%.4f", encryptTime))s (\(String(format: "%.2f", sizeKB / encryptTime / 1024)) MB/s)")
            print("  Decrypt: \(String(format: "%.4f", decryptTime))s (\(String(format: "%.2f", sizeKB / decryptTime / 1024)) MB/s)")
        }
    }

    /// Benchmark key derivation performance.
    func testKeyDerivationPerformance() throws {
        let mnemonic = ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                       "abandon", "abandon", "abandon", "abandon", "abandon", "about"]

        let derivationTime = try measureTime {
            for _ in 0..<100 {
                _ = try Encryption.deriveKey(mnemonic: mnemonic)
            }
        }

        print("Key Derivation Performance (100 iterations):")
        print("  Total time: \(String(format: "%.4f", derivationTime))s")
        print("  Average time: \(String(format: "%.6f", derivationTime / 100))s per derivation")
        print("  Derivations per second: \(String(format: "%.1f", 100 / derivationTime))")
    }

    /// Benchmark memory usage patterns.
    func testMemoryUsageBenchmark() async throws {
        print("Memory Usage Benchmark:")

        // Test with different object sizes
        let sizes = [100 * 1024, 1024 * 1024, 5 * 1024 * 1024] // 100KB, 1MB, 5MB

        for size in sizes {
            let testData = Data(repeating: 0x45, count: size)
            let key = "bench-memory-\(size / 1024)KB-\(UUID().uuidString)"

            // Measure memory during upload
            let beforeUpload = getMemoryUsage()
            try await s3Client.putObject(key: key, data: testData)
            let afterUpload = getMemoryUsage()

            // Measure memory during download
            let beforeDownload = getMemoryUsage()
            _ = try await s3Client.getObject(key: key)
            let afterDownload = getMemoryUsage()

            print("  \(size / 1024)KB object:")
            print("    Upload memory delta: \(afterUpload - beforeUpload) MB")
            print("    Download memory delta: \(afterDownload - beforeDownload) MB")

            // Clean up
            try await s3Client.deleteObject(key: key)
        }
    }

    // MARK: - Helper Methods

    /// Measure execution time of an async operation.
    private func measureTime(_ operation: () async throws -> Void) async rethrows -> TimeInterval {
        let start = Date()
        try await operation()
        return Date().timeIntervalSince(start)
    }

    /// Measure execution time of a sync operation.
    private func measureTime(_ operation: () throws -> Void) rethrows -> TimeInterval {
        let start = Date()
        try operation()
        return Date().timeIntervalSince(start)
    }

    /// Get current memory usage in MB (simplified).
    private func getMemoryUsage() -> Double {
        #if os(macOS)
        // This is a simplified memory check - in production you'd use more sophisticated tools
        return Double(ProcessInfo.processInfo.physicalMemory) / 1024 / 1024 / 1024 // Total system memory as proxy
        #else
        return 0.0 // Not implemented for other platforms
        #endif
    }
}