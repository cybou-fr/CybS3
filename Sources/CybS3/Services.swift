import Foundation
import ArgumentParser
import Crypto
import SwiftBIP39

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

// MARK: - config Service

struct ConfigService {
    static let configPath = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".cybs3")
        .appendingPathExtension("json")
    
    static func loadConfig() throws -> CybS3.AppConfig {
        guard FileManager.default.fileExists(atPath: configPath.path) else {
            return CybS3.AppConfig()
        }
        let data = try Data(contentsOf: configPath)
        return try JSONDecoder().decode(CybS3.AppConfig.self, from: data)
    }
    
    static func saveConfig(_ config: CybS3.AppConfig) throws {
        let data = try JSONEncoder().encode(config)
        
        if !FileManager.default.fileExists(atPath: configPath.path) {
            _ = FileManager.default.createFile(atPath: configPath.path, contents: nil, attributes: [.posixPermissions: 0o600])
        } else {
             try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configPath.path)
        }
        
        try data.write(to: configPath)
    }
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

// MARK: - Vault Service

struct VaultService {
    private static let vaultsPath = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".cybs3.vaults")
    
    static func loadVaults(mnemonic: [String]) throws -> [VaultConfig] {
        guard FileManager.default.fileExists(atPath: vaultsPath.path) else {
            return []
        }
        
        let encryptedData = try Data(contentsOf: vaultsPath)
        let key = try EncryptionService.deriveKey(mnemonic: mnemonic)
        let decryptedData = try EncryptionService.decrypt(data: encryptedData, key: key)
        let secureVaults = try JSONDecoder().decode(SecureVaults.self, from: decryptedData)
        return secureVaults.vaults
    }
    
    static func saveVaults(_ vaults: [VaultConfig], mnemonic: [String]) throws {
        let secureVaults = SecureVaults(vaults: vaults)
        let data = try JSONEncoder().encode(secureVaults)
        
        let key = try EncryptionService.deriveKey(mnemonic: mnemonic)
        let encryptedData = try EncryptionService.encrypt(data: data, key: key)
        
        if !FileManager.default.fileExists(atPath: vaultsPath.path) {
             _ = FileManager.default.createFile(atPath: vaultsPath.path, contents: nil, attributes: [.posixPermissions: 0o600])
        }
        try encryptedData.write(to: vaultsPath)
    }
    
    static func addVault(_ vault: VaultConfig, mnemonic: [String]) throws {
        var vaults = try loadVaults(mnemonic: mnemonic)
        vaults.append(vault)
        try saveVaults(vaults, mnemonic: mnemonic)
    }
    
    static func deleteVault(name: String, mnemonic: [String]) throws {
        var vaults = try loadVaults(mnemonic: mnemonic)
        guard let index = vaults.firstIndex(where: { $0.name == name }) else {
            throw VaultError.vaultNotFound(name)
        }
        vaults.remove(at: index)
        try saveVaults(vaults, mnemonic: mnemonic)
    }
    
    static func getVault(name: String, mnemonic: [String]) throws -> VaultConfig {
        let vaults = try loadVaults(mnemonic: mnemonic)
        guard let vault = vaults.first(where: { $0.name == name }) else {
            throw VaultError.vaultNotFound(name)
        }
        return vault
    }
}

enum VaultError: Error {
    case vaultNotFound(String)
}
