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
            guard let endpoint = InteractionService.prompt(message: "Enter S3 Endpoint (e.g. s3.amazonaws.com):"), !endpoint.isEmpty else { return }
            guard let accessKey = InteractionService.prompt(message: "Enter Access Key:"), !accessKey.isEmpty else { return }
            guard let secretKey = InteractionService.prompt(message: "Enter Secret Key:"), !secretKey.isEmpty else { return }
            
            let region = InteractionService.prompt(message: "Enter Region (default: us-east-1):") ?? "us-east-1"
            let finalRegion = region.isEmpty ? "us-east-1" : region
            
            let bucket = InteractionService.prompt(message: "Enter Bucket (optional):")
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
            let mnemonic: [String]
            do {
                mnemonic = try InteractionService.promptForMnemonic(purpose: "encrypt this vault")
            } catch {
                print("Error: \(error)")
                throw ExitCode.failure
            }
            
            // 3. Add via Service
            do {
                try VaultService.addVault(newVault, mnemonic: mnemonic)
                print("✅ Vault '\(name)' added successfully.")
            } catch {
                print("Error saving vault: \(error)")
                throw ExitCode.failure
            }
        }
    }
    
    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "list",
            abstract: "List all encrypted vaults"
        )
        
        func run() async throws {
            let mnemonic: [String]
            do {
                mnemonic = try InteractionService.promptForMnemonic(purpose: "decrypt vaults")
            } catch {
                print("Error: \(error)")
                throw ExitCode.failure
            }
            
            do {
                let vaults = try VaultService.loadVaults(mnemonic: mnemonic)
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
            let mnemonic: [String]
            do {
                mnemonic = try InteractionService.promptForMnemonic(purpose: "decrypt vaults")
            } catch {
                print("Error: \(error)")
                throw ExitCode.failure
            }
            
            do {
                try VaultService.deleteVault(name: name, mnemonic: mnemonic)
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
             let mnemonic: [String]
            do {
                mnemonic = try InteractionService.promptForMnemonic(purpose: "decrypt vaults")
            } catch {
                print("Error: \(error)")
                throw ExitCode.failure
            }
            
            do {
                let vault = try VaultService.getVault(name: name, mnemonic: mnemonic)
                
                // Apply to global config using ConfigService
                var config = try ConfigService.loadConfig()
                config.endpoint = vault.endpoint
                config.accessKey = vault.accessKey
                config.secretKey = vault.secretKey
                config.region = vault.region
                config.bucket = vault.bucket
                
                try ConfigService.saveConfig(config)
                
                print("✅ Vault '\(name)' selected. Configuration updated at \(ConfigService.configPath.path).")
                
            } catch {
                print("Error: \(error)")
                throw ExitCode.failure
            }
        }
    }
}
