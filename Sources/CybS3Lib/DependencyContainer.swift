import Foundation
import Crypto

/// Dependency injection container for managing service dependencies.
public protocol DependencyContainer {
    var s3Client: S3ClientProtocol { get }
    var encryptionService: EncryptionServiceProtocol { get }
    var keychainService: KeychainServiceProtocol { get }
    var configurationManager: ConfigurationManager { get }
    var metrics: Metrics.Type { get }
}

/// Protocol for S3 client operations.
public protocol S3ClientProtocol {
    func listObjects(prefix: String?, delimiter: String?, maxKeys: Int?) async throws -> [S3Object]
    func getObject(key: String) async throws -> Data
    func putObject(key: String, data: Data, metadata: [String: String]?) async throws
    func deleteObject(key: String) async throws
    func createBucketIfNotExists() async throws
}

/// Protocol for encryption operations.
public protocol EncryptionServiceProtocol {
    func deriveKey(mnemonic: [String]) throws -> SymmetricKey
    func encrypt(data: Data, key: SymmetricKey) throws -> Data
    func decrypt(data: Data, key: SymmetricKey) throws -> Data
}

/// Protocol for keychain/secure storage operations.
public protocol KeychainServiceProtocol {
    func store(_ data: Data, for key: String) throws
    func retrieve(for key: String) throws -> Data?
    func delete(for key: String) throws
}

/// Default dependency container implementation.
public final class DefaultContainer: DependencyContainer {
    public let s3Client: S3ClientProtocol
    public let encryptionService: EncryptionServiceProtocol
    public let keychainService: KeychainServiceProtocol
    public let configurationManager: ConfigurationManager
    public let metrics: Metrics.Type
    
    /// Initialize with default implementations.
    public init() {
        self.encryptionService = StaticEncryptionService()
        self.keychainService = SecureStorageFactory.create()
        self.configurationManager = ConfigurationManager.shared
        self.metrics = Metrics.self
        
        // S3Client needs configuration, so we create a basic one
        // In real usage, this would be configured properly
        let config = S3Client.Configuration()
        self.s3Client = S3Client(
            endpoint: S3Endpoint(host: "localhost", port: 9000, useSSL: false),
            accessKey: "",
            secretKey: "",
            bucket: "",
            region: "us-east-1"
        )
    }
    
    /// Initialize with custom implementations (for testing).
    public init(
        s3Client: S3ClientProtocol,
        encryptionService: EncryptionServiceProtocol,
        keychainService: KeychainServiceProtocol,
        configurationManager: ConfigurationManager,
        metrics: Metrics.Type
    ) {
        self.s3Client = s3Client
        self.encryptionService = encryptionService
        self.keychainService = keychainService
        self.configurationManager = configurationManager
        self.metrics = metrics
    }
}

/// Wrapper for static EncryptionService to conform to protocol.
private struct StaticEncryptionService: EncryptionServiceProtocol {
    func deriveKey(mnemonic: [String]) throws -> SymmetricKey {
        try EncryptionService.deriveKey(mnemonic: mnemonic)
    }
    
    func encrypt(data: Data, key: SymmetricKey) throws -> Data {
        try EncryptionService.encrypt(data: data, key: key)
    }
    
    func decrypt(data: Data, key: SymmetricKey) throws -> Data {
        try EncryptionService.decrypt(data: data, key: key)
    }
}

// MARK: - S3Client Protocol Conformance

extension S3Client: S3ClientProtocol {
    // S3Client already implements these methods, so this is just for protocol conformance
}

/// Global service locator for accessing dependencies.
public final class ServiceLocator {
    private static let lock = CrossPlatformLock()
    @MainActor private static var _container: DependencyContainer = DefaultContainer()
    
    /// Set the global dependency container.
    @MainActor public static func setContainer(_ container: DependencyContainer) {
        _container = container
    }
    
    /// Get the global dependency container.
    @MainActor public static var shared: DependencyContainer {
        _container
    }
}