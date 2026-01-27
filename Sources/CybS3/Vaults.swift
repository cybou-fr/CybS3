import Foundation
import ArgumentParser
import Crypto
import SwiftBIP39

struct VaultConfig: Codable {
    var name: String
    var endpoint: String
    var accessKey: String
    var secretKey: String
    var region: String
    var bucket: String?
}

// Wrapper for the encrypted file
struct SecureVaults: Codable {
    var version: Int = 1
    var vaults: [VaultConfig]
}

extension CybS3 {
    struct Vaults: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "vaults",
            abstract: "Manage encrypted S3 vaults",
            subcommands: [
                Add.self,
                List.self,
                Delete.self,
                Select.self
            ]
        )
    }
}

extension CybS3.Vaults {
    struct Add: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "add",
            abstract: "Add a new encrypted vault configuration"
        )
        
        @Option(name: .shortAndLong, help: "Vault name")
        var name: String
        
        func run() async throws {
            // 1. Gather Vault Details
            print("Enter S3 Endpoint (e.g. s3.amazonaws.com):")
            guard let endpoint = readLine(), !endpoint.isEmpty else { return }
            
            print("Enter Access Key:")
            guard let accessKey = readLine(), !accessKey.isEmpty else { return }
            
            print("Enter Secret Key:")
            guard let secretKey = readLine(), !secretKey.isEmpty else { return }
            
            print("Enter Region (default: us-east-1):")
            let region = readLine() ?? "us-east-1"
            let finalRegion = region.isEmpty ? "us-east-1" : region
            
            print("Enter Bucket (optional):")
            let bucket = readLine()
            let finalBucket = (bucket?.isEmpty ?? true) ? nil : bucket
            
            let newVault = VaultConfig(
                name: name,
                endpoint: endpoint,
                accessKey: accessKey,
                secretKey: secretKey,
                region: finalRegion,
                bucket: finalBucket
            )
            
            // 2. Get Mnemonic for Encryption
            print("\nEnter your 12-word Mnemonic to encrypt this vault:")
            guard let mnemonicStr = readLine(), !mnemonicStr.isEmpty else {
                print("Error: Mnemonic required.")
                throw ExitCode.failure
            }
            let mnemonic = mnemonicStr.components(separatedBy: .whitespacesAndNewlines).filter { !$0.isEmpty }
            
            do {
                try BIP39.validate(mnemonic: mnemonic)
            } catch {
                print("Error: Invalid mnemonic: \(error)")
                throw ExitCode.failure
            }
            
            // 3. Load existing vaults (if any) and append
            var currentVaults = try loadVaults(mnemonic: mnemonic)
            currentVaults.append(newVault)
            
            // 4. Save
            try saveVaults(currentVaults, mnemonic: mnemonic)
            print("✅ Vault '\(name)' added successfully.")
        }
    }
    
    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "list",
            abstract: "List all encrypted vaults"
        )
        
        func run() async throws {
            print("Enter your 12-word Mnemonic to decrypt vaults:")
            guard let mnemonicStr = readLine(), !mnemonicStr.isEmpty else {
                print("Error: Mnemonic required.")
                throw ExitCode.failure
            }
            let mnemonic = mnemonicStr.components(separatedBy: .whitespacesAndNewlines).filter { !$0.isEmpty }
            
            do {
                let vaults = try loadVaults(mnemonic: mnemonic)
                if vaults.isEmpty {
                    print("No vaults found.")
                    return
                }
                
                print("\nEncrypted Vaults:")
                print("------------------------------------------------")
                for vault in vaults {
                    print("Name: \(vault.name)")
                    print("Endpoint: \(vault.endpoint)")
                    print("Bucket: \(vault.bucket ?? "N/A")")
                    print("Region: \(vault.region)")
                    print("------------------------------------------------")
                }
            } catch {
                print("Error loading/decrypting vaults: \(error)")
                print("Make sure the mnemonic is correct and matches the one used to encrypt.")
                throw ExitCode.failure
            }
        }
    }
    struct Delete: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "delete",
            abstract: "Delete an encrypted vault configuration"
        )
        
        @Argument(help: "Name of the vault to delete")
        var name: String
        
        func run() async throws {
            print("Enter your 12-word Mnemonic to decrypt vaults:")
            guard let mnemonicStr = readLine(), !mnemonicStr.isEmpty else {
                print("Error: Mnemonic required.")
                throw ExitCode.failure
            }
            let mnemonic = mnemonicStr.components(separatedBy: .whitespacesAndNewlines).filter { !$0.isEmpty }
            
            do {
                var vaults = try loadVaults(mnemonic: mnemonic)
                
                guard let index = vaults.firstIndex(where: { $0.name == name }) else {
                    print("Error: Vault '\(name)' not found.")
                    throw ExitCode.failure
                }
                
                vaults.remove(at: index)
                try saveVaults(vaults, mnemonic: mnemonic)
                print("✅ Vault '\(name)' deleted successfully.")
            } catch {
                print("Error: \(error)")
                throw ExitCode.failure
            }
        }
    }

    struct Select: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "select",
            abstract: "Select a vault and apply its configuration globally"
        )
        
        @Argument(help: "Name of the vault to select")
        var name: String
        
        func run() async throws {
            print("Enter your 12-word Mnemonic to decrypt vaults:")
            guard let mnemonicStr = readLine(), !mnemonicStr.isEmpty else {
                print("Error: Mnemonic required.")
                throw ExitCode.failure
            }
            let mnemonic = mnemonicStr.components(separatedBy: .whitespacesAndNewlines).filter { !$0.isEmpty }
            
            do {
                let vaults = try loadVaults(mnemonic: mnemonic)
                
                guard let vault = vaults.first(where: { $0.name == name }) else {
                    print("Error: Vault '\(name)' not found.")
                    throw ExitCode.failure
                }
                
                // Apply to global config
                let configPath = FileManager.default.homeDirectoryForCurrentUser
                    .appendingPathComponent(".cybs3")
                    .appendingPathExtension("json")
                
                var config = CybS3.AppConfig()
                config.endpoint = vault.endpoint
                config.accessKey = vault.accessKey
                config.secretKey = vault.secretKey
                config.region = vault.region
                config.bucket = vault.bucket
                
                let data = try JSONEncoder().encode(config)
                
                if !FileManager.default.fileExists(atPath: configPath.path) {
                    _ = FileManager.default.createFile(atPath: configPath.path, contents: nil, attributes: [.posixPermissions: 0o600])
                } else {
                     try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configPath.path)
                }
                
                try data.write(to: configPath)
                print("✅ Vault '\(name)' selected. Configuration updated at \(configPath.path).")
                
            } catch {
                print("Error: \(error)")
                throw ExitCode.failure
            }
        }
    }
}

// Helpers
private func getVaultsFilePath() -> URL {
    return FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".cybs3.vaults")
}

private func loadVaults(mnemonic: [String]) throws -> [VaultConfig] {
    let file = getVaultsFilePath()
    guard FileManager.default.fileExists(atPath: file.path) else {
        return []
    }
    
    let encryptedData = try Data(contentsOf: file)
    let key = Encryption.deriveKey(mnemonic: mnemonic)
    
    do {
        let decryptedData = try Encryption.decrypt(data: encryptedData, key: key)
        let secureVaults = try JSONDecoder().decode(SecureVaults.self, from: decryptedData)
        return secureVaults.vaults
    } catch {
        print("Decryption failed. Ensure your mnemonic is correct.")
        throw error
    }
}

private func saveVaults(_ vaults: [VaultConfig], mnemonic: [String]) throws {
    let file = getVaultsFilePath()
    let secureVaults = SecureVaults(vaults: vaults)
    let data = try JSONEncoder().encode(secureVaults)
    
    let key = Encryption.deriveKey(mnemonic: mnemonic)
    let encryptedData = try Encryption.encrypt(data: data, key: key)
    
    if !FileManager.default.fileExists(atPath: file.path) {
         _ = FileManager.default.createFile(atPath: file.path, contents: nil, attributes: [.posixPermissions: 0o600])
    }
    try encryptedData.write(to: file)
}
