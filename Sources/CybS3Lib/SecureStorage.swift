import Foundation
import Crypto

/// Protocol for secure storage implementations across different platforms.
public protocol SecureStorage: KeychainServiceProtocol {
    /// Store data securely for a given key.
    func store(_ data: Data, for key: String) throws
    
    /// Retrieve data for a given key.
    func retrieve(for key: String) throws -> Data?
    
    /// Delete data for a given key.
    func delete(for key: String) throws
}

/// Platform-specific secure storage implementations.
public enum SecureStorageFactory {
    /// Create the appropriate secure storage for the current platform.
    public static func create() -> SecureStorage {
        #if os(macOS)
        return KeychainStorage()
        #elseif os(Windows)
        return WindowsCredentialStorage()
        #else
        return FileBasedStorage()
        #endif
    }
}

#if os(macOS)
import Security

/// macOS Keychain-based secure storage.
public final class KeychainStorage: SecureStorage {
    private let serviceName = "com.cybs3.cli"
    
    public init() {}
    
    public func store(_ data: Data, for key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ]
        
        // Delete existing item if it exists
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.operationFailed(status: status)
        }
    }
    
    public func retrieve(for key: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecItemNotFound {
            return nil
        }
        
        guard status == errSecSuccess else {
            throw KeychainError.operationFailed(status: status)
        }
        
        return result as? Data
    }
    
    public func delete(for key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeychainError.operationFailed(status: status)
        }
    }
}
#endif

#if os(Windows)
// Windows Credential Manager implementation would go here
// For now, we'll use file-based storage as fallback
#endif

/// File-based secure storage for platforms without native secure storage.
public final class FileBasedStorage: SecureStorage {
    private let storageDirectory: URL
    
    public init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        storageDirectory = appSupport.appendingPathComponent("CybS3", isDirectory: true)
        
        // Create directory if it doesn't exist
        try? FileManager.default.createDirectory(at: storageDirectory, withIntermediateDirectories: true)
    }
    
    public func store(_ data: Data, for key: String) throws {
        let fileURL = storageDirectory.appendingPathComponent(key)
        
        // Encrypt data before storing (basic protection)
        let encryptedData = try basicEncrypt(data)
        
        try encryptedData.write(to: fileURL, options: .atomic)
        
        // Set restrictive permissions
        try setRestrictivePermissions(for: fileURL)
    }
    
    public func retrieve(for key: String) throws -> Data? {
        let fileURL = storageDirectory.appendingPathComponent(key)
        
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }
        
        let encryptedData = try Data(contentsOf: fileURL)
        return try basicDecrypt(encryptedData)
    }
    
    public func delete(for key: String) throws {
        let fileURL = storageDirectory.appendingPathComponent(key)
        
        if FileManager.default.fileExists(atPath: fileURL.path) {
            try FileManager.default.removeItem(at: fileURL)
        }
    }
    
    /// Basic encryption using a simple key derived from the app name.
    private func basicEncrypt(_ data: Data) throws -> Data {
        let key = "cybs3-file-storage-key".data(using: .utf8)!
        return try Encryption.encrypt(data: data, key: SymmetricKey(data: key))
    }
    
    /// Basic decryption.
    private func basicDecrypt(_ data: Data) throws -> Data {
        let key = "cybs3-file-storage-key".data(using: .utf8)!
        return try Encryption.decrypt(data: data, key: SymmetricKey(data: key))
    }
    
    /// Set restrictive file permissions (owner read/write only).
    private func setRestrictivePermissions(for fileURL: URL) throws {
        #if os(macOS) || os(Linux)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        #endif
    }
}