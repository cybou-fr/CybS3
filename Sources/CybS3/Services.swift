import Foundation
import ArgumentParser
import Crypto
import SwiftBIP39

// MARK: - Models

struct AppSettings: Codable {
    var defaultRegion: String?
    var defaultBucket: String?
    var defaultEndpoint: String?
    var defaultAccessKey: String?
    var defaultSecretKey: String?
}

struct VaultConfig: Codable {
    var name: String
    var endpoint: String
    var accessKey: String
    var secretKey: String
    var region: String
    var bucket: String?
}

struct EncryptedConfig: Codable {
    var version: Int = 2
    /// Base64 encoded Data Key (32 bytes). Protected by the Master Key (Mnemonic).
    /// This key is used to encrypt/decrypt S3 files.
    var dataKey: Data
    var activeVaultName: String?
    var vaults: [VaultConfig]
    var settings: AppSettings
}

enum StorageError: Error {
    case configNotFound
    case oldVaultsFoundButMigrationFailed
    case decryptionFailed
}

// MARK: - Storage Service

struct StorageService {
    private static let configDir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".cybs3")
    
    private static let configPath = configDir.appendingPathComponent("config.enc")
    
    // Legacy paths
    private static let legacyConfigPath = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".cybs3.json")
    private static let legacyVaultsPath = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".cybs3.vaults")

    /// Loads the configuration, attempting migration if necessary.
    /// Returns the Config and the derived Data Key (SymmetricKey) ready for use.
    static func load(mnemonic: [String]) throws -> (EncryptedConfig, SymmetricKey) {
        
        // 1. Ensure directory exists
        if !FileManager.default.fileExists(atPath: configDir.path) {
            try FileManager.default.createDirectory(at: configDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        
        // 2. Check for legacy migration
        if !FileManager.default.fileExists(atPath: configPath.path) {
            if FileManager.default.fileExists(atPath: legacyVaultsPath.path) || FileManager.default.fileExists(atPath: legacyConfigPath.path) {
                 print("Migrating legacy configuration to new encrypted format...")
                 return try migrate(mnemonic: mnemonic)
            }
            
            // New User: Create fresh config
            // Generate NEW random Data Key
            let newDataKey = SymmetricKey(size: .bits256)
            let config = EncryptedConfig(
                dataKey: newDataKey.withUnsafeBytes { Data($0) },
                activeVaultName: nil,
                vaults: [],
                settings: AppSettings()
            )
            try save(config, mnemonic: mnemonic)
            return (config, newDataKey)
        }
        
        // 3. Normal Load
        let encryptedData = try Data(contentsOf: configPath)
        let masterKey = try EncryptionService.deriveKey(mnemonic: mnemonic)
        
        let decryptedData = try EncryptionService.decrypt(data: encryptedData, key: masterKey)
        let config = try JSONDecoder().decode(EncryptedConfig.self, from: decryptedData)
        
        let dataKey = SymmetricKey(data: config.dataKey)
        return (config, dataKey)
    }
    
    static func save(_ config: EncryptedConfig, mnemonic: [String]) throws {
        let masterKey = try EncryptionService.deriveKey(mnemonic: mnemonic)
        let data = try JSONEncoder().encode(config)
        let encryptedData = try EncryptionService.encrypt(data: data, key: masterKey)
        
        if !FileManager.default.fileExists(atPath: configPath.path) {
             _ = FileManager.default.createFile(atPath: configPath.path, contents: nil, attributes: [.posixPermissions: 0o600])
        } else {
             try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configPath.path)
        }
        
        try encryptedData.write(to: configPath)
    }
    
    /// Rotates the Master Key (Mnemonic) while preserving the internal Data Key.
    static func rotateKey(oldMnemonic: [String], newMnemonic: [String]) throws {
        let (config, _) = try load(mnemonic: oldMnemonic)
        try save(config, mnemonic: newMnemonic)
        print("✅ Configuration re-encrypted with new mnemonic. Data Key preserved.")
    }
    
    private static func migrate(mnemonic: [String]) throws -> (EncryptedConfig, SymmetricKey) {
        var vaults: [VaultConfig] = []
        var settings = AppSettings()
        
        // Load legacy vaults
        if FileManager.default.fileExists(atPath: legacyVaultsPath.path) {
            // Decrypt legacy vaults using the mnemonic (as mostly likely it was used)
            // Legacy encryption logic was: deriveKey(mnemonic) -> decrypt
            let masterKey = try EncryptionService.deriveKey(mnemonic: mnemonic)
            let encryptedData = try Data(contentsOf: legacyVaultsPath)
            do {
                let decryptedData = try EncryptionService.decrypt(data: encryptedData, key: masterKey)
                // Legacy wrapper was SecureVaults
                struct LegacySecureVaults: Codable {
                    var vaults: [VaultConfig]
                }
                let secureVaults = try JSONDecoder().decode(LegacySecureVaults.self, from: decryptedData)
                vaults = secureVaults.vaults
            } catch {
                print("Error decrypting legacy vaults: \(error)")
                print("Ensure you provided the correct mnemonic used for the OLD vaults.")
                throw StorageError.decryptionFailed
            }
        }
        
        // Legacy legacyConfig models
        struct LegacyAppConfig: Codable {
            var region: String?
            var bucket: String?
            var endpoint: String?
            var accessKey: String?
            var secretKey: String?
        }
        
        // Load legacy config (Plaintext)
        if FileManager.default.fileExists(atPath: legacyConfigPath.path) {
            let data = try Data(contentsOf: legacyConfigPath)
            let legacyAppConfig = try JSONDecoder().decode(LegacyAppConfig.self, from: data)
            settings.defaultRegion = legacyAppConfig.region
            settings.defaultBucket = legacyAppConfig.bucket
            settings.defaultEndpoint = legacyAppConfig.endpoint
            settings.defaultAccessKey = legacyAppConfig.accessKey
            settings.defaultSecretKey = legacyAppConfig.secretKey
        }
        
        // CRITICAL: Preserve the Data Key
        // In the legacy system, file encryption used `deriveKey(mnemonic)`.
        // To keep files readable, our new `Data Key` MUST be the result of `deriveKey(mnemonic)`.
        // This effectively "freezes" the current specific mnemonic's derived key as the persistent Data Key.
        let legacyDerivedKey = try EncryptionService.deriveKey(mnemonic: mnemonic)
        let dataKeyBytes = legacyDerivedKey.withUnsafeBytes { Data($0) }
        
        let config = EncryptedConfig(
            dataKey: dataKeyBytes,
            activeVaultName: nil, // Legacy didn't really track active vault well, or we ignore it
            vaults: vaults,
            settings: settings
        )
        
        // Save new config
        try save(config, mnemonic: mnemonic)
        
        // Rename legacy files
        try? FileManager.default.moveItem(at: legacyVaultsPath, to: legacyVaultsPath.appendingPathExtension("bak"))
        try? FileManager.default.moveItem(at: legacyConfigPath, to: legacyConfigPath.appendingPathExtension("bak"))
        
        print("Migration complete. Legacy files backed up to .bak")
        
        return (config, legacyDerivedKey)
    }
}

// MARK: - Interaction Service

struct InteractionService {
    static func prompt(message: String) -> String? {
        print(message)
        return readLine()?.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    
    static func promptForMnemonic(purpose: String) throws -> [String] {
        print("Enter your 12-word Mnemonic to \(purpose):")
        guard let mnemonicStr = readLine(), !mnemonicStr.isEmpty else {
            throw InteractionError.mnemonicRequired
        }
        let mnemonic = mnemonicStr.components(separatedBy: .whitespacesAndNewlines).filter { !$0.isEmpty }
        
        try BIP39.validate(mnemonic: mnemonic, language: .english)
        return mnemonic
    }
}

enum InteractionError: Error {
    case mnemonicRequired
}

// MARK: - Encryption Service

struct EncryptionService {
    static func deriveKey(mnemonic: [String]) throws -> SymmetricKey {
        return try Encryption.deriveKey(mnemonic: mnemonic)
    }
    
    static func encrypt(data: Data, key: SymmetricKey) throws -> Data {
        return try Encryption.encrypt(data: data, key: key)
    }
    
    static func decrypt(data: Data, key: SymmetricKey) throws -> Data {
        return try Encryption.decrypt(data: data, key: key)
    }
}
