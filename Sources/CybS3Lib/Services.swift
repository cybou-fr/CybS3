import Foundation
#if os(macOS)
import Darwin
#else
import Glibc
#endif
import ArgumentParser
import Crypto
import SwiftBIP39

// MARK: - Models

/// Stores application-wide defaults.
public struct AppSettings: Codable {
    /// Default AWS Region.
    public var defaultRegion: String?
    /// Default S3 Bucket.
    public var defaultBucket: String?
    /// Default S3 Endpoint.
    public var defaultEndpoint: String?
    /// Default Access Key ID.
    public var defaultAccessKey: String?
    /// Default Secret Access Key.
    public var defaultSecretKey: String?
    
    public init(defaultRegion: String? = nil, defaultBucket: String? = nil, defaultEndpoint: String? = nil, defaultAccessKey: String? = nil, defaultSecretKey: String? = nil) {
        self.defaultRegion = defaultRegion
        self.defaultBucket = defaultBucket
        self.defaultEndpoint = defaultEndpoint
        self.defaultAccessKey = defaultAccessKey
        self.defaultSecretKey = defaultSecretKey
    }
}

/// Stores configuration for a specific encrypted vault.
public struct VaultConfig: Codable {
    /// The display name of the vault.
    public var name: String
    /// The S3 endpoint URL.
    public var endpoint: String
    /// The Access Key ID.
    public var accessKey: String
    /// The Secret Access Key.
    public var secretKey: String
    /// The AWS Region.
    public var region: String
    /// The associated S3 Bucket (optional).
    public var bucket: String?
    
    public init(name: String, endpoint: String, accessKey: String, secretKey: String, region: String, bucket: String? = nil) {
        self.name = name
        self.endpoint = endpoint
        self.accessKey = accessKey
        self.secretKey = secretKey
        self.region = region
        self.bucket = bucket
    }
}

/// The root configuration object that is encrypted and stored on disk.
public struct EncryptedConfig: Codable {
    /// Schema version.
    public var version: Int = 2
    /// Base64 encoded Data Key (32 bytes). Protected by the Master Key (Mnemonic).
    /// This key is used to encrypt/decrypt S3 files.
    public var dataKey: Data
    /// The name of the currently active vault.
    public var activeVaultName: String?
    /// List of configured vaults.
    public var vaults: [VaultConfig]
    /// Application settings.
    public var settings: AppSettings
    
    public init(dataKey: Data, activeVaultName: String? = nil, vaults: [VaultConfig], settings: AppSettings) {
        self.dataKey = dataKey
        self.activeVaultName = activeVaultName
        self.vaults = vaults
        self.settings = settings
    }
}

public enum StorageError: Error, LocalizedError {
    case configNotFound
    case oldVaultsFoundButMigrationFailed
    case decryptionFailed
    case integrityCheckFailed
    case unsupportedVersion(Int)
    
    public var errorDescription: String? {
        switch self {
        case .configNotFound:
            return "❌ Configuration not found. Run 'cybs3 login' to create one."
        case .oldVaultsFoundButMigrationFailed:
            return "❌ Legacy configuration migration failed. Ensure you provided the correct mnemonic."
        case .decryptionFailed:
            return "❌ Decryption failed. The mnemonic may be incorrect."
        case .integrityCheckFailed:
            return "❌ Configuration integrity check failed. The file may be corrupted."
        case .unsupportedVersion(let version):
            return "❌ Unsupported configuration version (\(version)). Please update CybS3."
        }
    }
}

// MARK: - Storage Service

/// Manages the persistence of the application configuration.
///
/// The configuration is stored in `~/.cybs3/config.enc`.
/// It is encrypted using a Master Key derived from the user's Mnemonic.
///
/// File format (v2): HMAC-SHA256 (32 bytes) || AES-GCM encrypted JSON
public struct StorageService {
    private static let configDir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".cybs3")
    
    private static let configPath = configDir.appendingPathComponent("config.enc")
    
    // Legacy paths
    private static let legacyConfigPath = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".cybs3.json")
    private static let legacyVaultsPath = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".cybs3.vaults")
    
    /// Current config format version
    private static let currentVersion = 2
    
    /// HMAC size in bytes
    private static let hmacSize = 32
    
    /// Secure file permissions (owner read/write only)
    private static let secureFilePermissions: Int16 = 0o600
    
    /// Secure directory permissions (owner read/write/execute only)
    private static let secureDirPermissions: Int16 = 0o700

    /// Loads the configuration, attempting migration if necessary.
    ///
    /// - Parameter mnemonic: The user's mnemonic phrase used to derive the Master Key.
    /// - Returns: A tuple containing the `EncryptedConfig` and the `SymmetricKey` (Data Key) ready for use.
    /// - Throws: `StorageError` or `EncryptionError` if loading fails.
    public static func load(mnemonic: [String]) throws -> (EncryptedConfig, SymmetricKey) {
        
        // 1. Ensure directory exists
        if !FileManager.default.fileExists(atPath: configDir.path) {
            try FileManager.default.createDirectory(at: configDir, withIntermediateDirectories: true, attributes: [.posixPermissions: secureDirPermissions])
        } else {
            // Verify and fix directory permissions if needed
            try? FileManager.default.setAttributes([.posixPermissions: secureDirPermissions], ofItemAtPath: configDir.path)
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
        
        // 3. Normal Load with integrity check
        let fileData = try Data(contentsOf: configPath)
        let masterKey = try EncryptionService.deriveKey(mnemonic: mnemonic)
        
        // Check if file has HMAC prefix (v2 format)
        let encryptedData: Data
        if fileData.count > hmacSize {
            let storedHmac = fileData.prefix(hmacSize)
            let payload = fileData.dropFirst(hmacSize)
            
            // Verify HMAC
            let computedHmac = try computeHMAC(data: Data(payload), key: masterKey)
            if storedHmac != computedHmac {
                // Try v1 format (no HMAC) for backward compatibility
                encryptedData = fileData
            } else {
                encryptedData = Data(payload)
            }
        } else {
            encryptedData = fileData
        }
        
        do {
            let decryptedData = try EncryptionService.decrypt(data: encryptedData, key: masterKey)
            var config = try JSONDecoder().decode(EncryptedConfig.self, from: decryptedData)
            
            // Check version and migrate if needed
            if config.version > currentVersion {
                throw StorageError.unsupportedVersion(config.version)
            }
            
            // Upgrade config if it's an older version
            if config.version < currentVersion {
                config.version = currentVersion
                try save(config, mnemonic: mnemonic)
            }
            
            let dataKey = SymmetricKey(data: config.dataKey)
            return (config, dataKey)
        } catch is DecodingError {
            throw StorageError.decryptionFailed
        }
    }
    
    /// Computes HMAC-SHA256 for integrity verification.
    private static func computeHMAC(data: Data, key: SymmetricKey) throws -> Data {
        let hmac = HMAC<SHA256>.authenticationCode(for: data, using: key)
        return Data(hmac)
    }
    
    /// Encrypts and saves the configuration to disk with integrity protection.
    ///
    /// - Parameters:
    ///   - config: The configuration object to save.
    ///   - mnemonic: The mnemonic used to encrypt the file.
    public static func save(_ config: EncryptedConfig, mnemonic: [String]) throws {
        let masterKey = try EncryptionService.deriveKey(mnemonic: mnemonic)
        
        var configToSave = config
        configToSave.version = currentVersion
        
        let data = try JSONEncoder().encode(configToSave)
        let encryptedData = try EncryptionService.encrypt(data: data, key: masterKey)
        
        // Compute HMAC for integrity
        let hmac = try computeHMAC(data: encryptedData, key: masterKey)
        
        // Write: HMAC || EncryptedData
        var fileData = hmac
        fileData.append(encryptedData)
        
        if !FileManager.default.fileExists(atPath: configPath.path) {
             _ = FileManager.default.createFile(atPath: configPath.path, contents: nil, attributes: [.posixPermissions: secureFilePermissions])
        } else {
             try FileManager.default.setAttributes([.posixPermissions: secureFilePermissions], ofItemAtPath: configPath.path)
        }
        
        try fileData.write(to: configPath)
    }
    
    /// Encrypts and saves the configuration to disk using a provided data key.
    ///
    /// - Parameters:
    ///   - config: The configuration object to save.
    ///   - dataKey: The symmetric key to use for encryption.
    public static func save(config: EncryptedConfig, dataKey: SymmetricKey) throws {
        var configToSave = config
        configToSave.version = currentVersion
        
        let data = try JSONEncoder().encode(configToSave)
        let encryptedData = try EncryptionService.encrypt(data: data, key: dataKey)
        
        // Compute HMAC for integrity
        let hmac = try computeHMAC(data: encryptedData, key: dataKey)
        
        // Write: HMAC || EncryptedData
        var fileData = hmac
        fileData.append(encryptedData)
        
        if !FileManager.default.fileExists(atPath: configPath.path) {
             _ = FileManager.default.createFile(atPath: configPath.path, contents: nil, attributes: [.posixPermissions: secureFilePermissions])
        } else {
             try FileManager.default.setAttributes([.posixPermissions: secureFilePermissions], ofItemAtPath: configPath.path)
        }
        
        try fileData.write(to: configPath)
    }
    
    /// Rotates the Master Key (Mnemonic) while preserving the internal Data Key.
    ///
    /// This allows the user to change their login mnemonic without losing access to their encrypted S3 data,
    /// because the Data Key (stored inside the config) is preserved and re-encrypted with the new mnemonic.
    public static func rotateKey(oldMnemonic: [String], newMnemonic: [String]) throws {
        let (config, _) = try load(mnemonic: oldMnemonic)
        try save(config, mnemonic: newMnemonic)
        print("✅ Configuration re-encrypted with new mnemonic. Data Key preserved.")
    }
    
    /// Migrates legacy configuration formats to the new `EncryptedConfig`.
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
        let dataKeyBytes = legacyDerivedKey.withUnsafeBytes { bytes in Data(bytes) }
        
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

/// Helper service for CLI user interaction.
public struct InteractionService {
    /// Prompts the user with a message and returns the input.
    public static func prompt(message: String) -> String? {
        print(message)
        return readLine()?.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    
    /// Prompts the user to enter their mnemonic phrase.
    ///
    /// Validates that the input is a valid 12-word BIP39 english mnemonic.
    public static func promptForMnemonic(purpose: String) throws -> [String] {
        print("Enter your 12-word Mnemonic to \(purpose):")
        guard let mnemonicStr = readLine(), !mnemonicStr.isEmpty else {
            throw InteractionError.mnemonicRequired
        }
        let mnemonic = mnemonicStr.components(separatedBy: .whitespacesAndNewlines).filter { !$0.isEmpty }
        
        try BIP39.validate(mnemonic: mnemonic, language: .english)
        return mnemonic
    }
    
    /// Prompts the user to enter a bucket name.
    public static func promptForBucket() throws -> String {
        print("Enter bucket name:")
        guard let bucket = readLine()?.trimmingCharacters(in: .whitespacesAndNewlines), !bucket.isEmpty else {
            throw InteractionError.bucketRequired
        }
        return bucket
    }
    
    /// Prompts the user to select a vault from a list.
    ///
    /// - Parameter vaults: The available vaults.
    /// - Returns: The selected vault, or nil if cancelled.
    public static func promptForVault(vaults: [VaultConfig]) -> VaultConfig? {
        guard !vaults.isEmpty else {
            print("❌ No vaults configured. Run 'cybs3 vaults add --name <name>' to create one.")
            return nil
        }
        
        print("\n📂 Select a vault:")
        print(String(repeating: "-", count: 40))
        
        for (index, vault) in vaults.enumerated() {
            let bucketInfo = vault.bucket.map { " (\($0))" } ?? ""
            print("  \(index + 1). \(vault.name)\(bucketInfo)")
            print("     └─ \(vault.endpoint)")
        }
        
        print(String(repeating: "-", count: 40))
        print("Enter number (or 'q' to cancel): ", terminator: "")
        
        guard let input = readLine()?.trimmingCharacters(in: .whitespaces) else {
            return nil
        }
        
        if input.lowercased() == "q" {
            return nil
        }
        
        guard let index = Int(input), index >= 1, index <= vaults.count else {
            print("❌ Invalid selection.")
            return nil
        }
        
        return vaults[index - 1]
    }
    
    /// Prompts for confirmation.
    ///
    /// - Parameters:
    ///   - message: The confirmation message.
    ///   - defaultValue: The default value if user just presses Enter.
    /// - Returns: True if confirmed, false otherwise.
    public static func confirm(message: String, defaultValue: Bool = false) -> Bool {
        let hint = defaultValue ? "[Y/n]" : "[y/N]"
        print("\(message) \(hint) ", terminator: "")
        
        guard let input = readLine()?.trimmingCharacters(in: .whitespaces).lowercased() else {
            return defaultValue
        }
        
        if input.isEmpty {
            return defaultValue
        }
        
        return input == "y" || input == "yes"
    }
}

public enum InteractionError: Error, LocalizedError {
    case mnemonicRequired
    case bucketRequired
    case invalidMnemonic(String)
    case userCancelled
    
    public var errorDescription: String? {
        switch self {
        case .mnemonicRequired:
            return "❌ Mnemonic is required. Run 'cybs3 keys create' to generate one."
        case .bucketRequired:
            return "❌ Bucket name is required. Use --bucket or set a default with 'cybs3 config --bucket <name>'."
        case .invalidMnemonic(let reason):
            return "❌ Invalid mnemonic: \(reason)"
        case .userCancelled:
            return "Operation cancelled by user."
        }
    }
}

// MARK: - Encryption Service

public struct EncryptionService {
    public static func deriveKey(mnemonic: [String]) throws -> SymmetricKey {
        return try Encryption.deriveKey(mnemonic: mnemonic)
    }
    
    public static func encrypt(data: Data, key: SymmetricKey) throws -> Data {
        return try Encryption.encrypt(data: data, key: key)
    }
    
    public static func decrypt(data: Data, key: SymmetricKey) throws -> Data {
        return try Encryption.decrypt(data: data, key: key)
    }
}
