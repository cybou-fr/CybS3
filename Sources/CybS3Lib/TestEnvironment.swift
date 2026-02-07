import Foundation
import CybS3Lib

/// Test environment setup for integration tests.
public struct TestEnvironment {
    /// Configuration for test S3 server.
    public struct S3TestConfig {
        public let endpoint: String
        public let accessKey: String
        public let secretKey: String
        public let bucket: String
        public let region: String
        
        public init(
            endpoint: String = "http://localhost:9000",
            accessKey: String = "minioadmin",
            secretKey: String = "minioadmin",
            bucket: String = "test-bucket",
            region: String = "us-east-1"
        ) {
            self.endpoint = endpoint
            self.accessKey = accessKey
            self.secretKey = secretKey
            self.bucket = bucket
            self.region = region
        }
    }
    
    /// Run a test with MinIO server setup.
    ///
    /// - Parameters:
    ///   - config: Test configuration.
    ///   - test: The test closure to execute.
    /// - Returns: The result of the test.
    public static func withMinIO(
        config: S3TestConfig = S3TestConfig(),
        test: (S3Client) async throws -> Void
    ) async throws {
        // Check if MinIO is available
        guard await isMinIOAvailable(at: config.endpoint) else {
            throw TestEnvironmentError.minioNotAvailable
        }
        
        let client = S3Client(
            endpoint: S3Endpoint(host: "localhost", port: 9000, useSSL: false),
            accessKey: config.accessKey,
            secretKey: config.secretKey,
            bucket: config.bucket,
            region: config.region
        )
        
        // Ensure bucket exists
        do {
            try await client.createBucketIfNotExists()
        } catch {
            // Bucket might already exist, continue
        }
        
        try await test(client)
        
        // Cleanup
        try await cleanupTestData(client: client)
    }
    
    /// Check if MinIO server is available.
    private static func isMinIOAvailable(at endpoint: String) async -> Bool {
        guard let url = URL(string: endpoint) else { return false }
        
        do {
            let (_, response) = try await URLSession.shared.data(from: url)
            return (response as? HTTPURLResponse)?.statusCode == 200
        } catch {
            return false
        }
    }
    
    /// Clean up test data.
    private static func cleanupTestData(client: S3Client) async throws {
        // List and delete all objects in the test bucket
        let objects = try await client.listObjects(prefix: nil, delimiter: nil)
        for object in objects where !object.isDirectory {
            try await client.deleteObject(key: object.key)
        }
    }
}

/// Test environment errors.
public enum TestEnvironmentError: Error, LocalizedError {
    case minioNotAvailable
    
    public var errorDescription: String? {
        switch self {
        case .minioNotAvailable:
            return "MinIO test server is not available. Please start MinIO with: docker run -p 9000:9000 minio/minio server /data"
        }
    }
}