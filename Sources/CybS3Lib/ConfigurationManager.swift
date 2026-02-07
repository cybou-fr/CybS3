import Foundation
import Crypto

/// Actor-based configuration manager for thread-safe access to shared configuration state.
public actor ConfigurationManager {
    /// Shared instance for global access.
    public static let shared = ConfigurationManager()
    
    /// Cached configuration instance.
    private var config: EncryptedConfig?
    
    /// Timestamp of last configuration load.
    private var lastLoadTime: Date?
    
    /// Cache validity duration in seconds.
    private let cacheValidity: TimeInterval = 300 // 5 minutes
    
    private init() {}
    
    /// Loads the configuration, using cache if valid.
    ///
    /// - Parameter mnemonic: The mnemonic to unlock the configuration.
    /// - Returns: The decrypted configuration.
    /// - Throws: An error if loading fails.
    public func load(mnemonic: [String]) async throws -> EncryptedConfig {
        // Check if we have a valid cached config
        if let cached = config, let lastLoad = lastLoadTime,
           Date().timeIntervalSince(lastLoad) < cacheValidity {
            return cached
        }
        
        // Load fresh configuration
        let (loaded, _) = try StorageService.load(mnemonic: mnemonic)
        config = loaded
        lastLoadTime = Date()
        
        return loaded
    }
    
    /// Invalidates the cached configuration.
    public func invalidateCache() {
        config = nil
        lastLoadTime = nil
    }
    
    /// Updates the configuration and refreshes the cache.
    ///
    /// - Parameters:
    ///   - config: The new configuration.
    ///   - dataKey: The encryption key for the configuration.
    /// - Throws: An error if saving fails.
    public func update(config: EncryptedConfig, dataKey: SymmetricKey) async throws {
        try StorageService.save(config: config, dataKey: dataKey)
        self.config = config
        lastLoadTime = Date()
    }
}