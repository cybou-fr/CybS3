import Foundation
import ArgumentParser
import Crypto
import SwiftBIP39
import CybS3Lib

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
    /// Command to add a new encrypted vault configuration.
    struct Add: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "add",
            abstract: "Add a new encrypted vault configuration"
        )
        
        @Option(name: .shortAndLong, help: "Vault name")
        var name: String
        
        func run() async throws {
            // 1. Authenticate first to load config
            let mnemonic = try InteractionService.promptForMnemonic(purpose: "unlock configuration")
            var (config, _) = try StorageService.load(mnemonic: mnemonic)
            
            // 2. Gather Vault Details
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
            
            // 3. Save
            config.vaults.append(newVault)
            try StorageService.save(config, mnemonic: mnemonic)
            print("✅ Vault '\(name)' added successfully.")
        }
    }
    
    /// Command to list all configured vaults.
    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "list",
            abstract: "List all encrypted vaults"
        )
        
        func run() async throws {
            let mnemonic = try InteractionService.promptForMnemonic(purpose: "unlock configuration")
            let (config, _) = try StorageService.load(mnemonic: mnemonic)
            
            if config.vaults.isEmpty {
                print("No vaults found.")
                return
            }
            
            print("\nEncrypted Vaults:")
            print("------------------------------------------------")
            for vault in config.vaults {
                print("Name: \(vault.name)")
                print("Endpoint: \(vault.endpoint)")
                print("Bucket: \(vault.bucket ?? "N/A")")
                print("Region: \(vault.region)")
                print("------------------------------------------------")
            }
        }
    }
    
    /// Command to delete a configured vault.
    struct Delete: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "delete",
            abstract: "Delete an encrypted vault configuration"
        )
        
        @Argument(help: "Name of the vault to delete")
        var name: String
        
        func run() async throws {
            let mnemonic = try InteractionService.promptForMnemonic(purpose: "unlock configuration")
            var (config, _) = try StorageService.load(mnemonic: mnemonic)
            
            guard let index = config.vaults.firstIndex(where: { $0.name == name }) else {
                print("Error: Vault '\(name)' not found.")
                throw ExitCode.failure
            }
            
            config.vaults.remove(at: index)
            try StorageService.save(config, mnemonic: mnemonic)
            print("✅ Vault '\(name)' deleted successfully.")
        }
    }

    /// Command to select a vault and apply its settings globally.
    struct Select: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "select",
            abstract: "Select a vault and apply its configuration globally"
        )
        
        @Argument(help: "Name of the vault to select")
        var name: String
        
        func run() async throws {
            let mnemonic = try InteractionService.promptForMnemonic(purpose: "unlock configuration")
            var (config, _) = try StorageService.load(mnemonic: mnemonic)
            
            guard let vault = config.vaults.first(where: { $0.name == name }) else {
                 print("Error: Vault '\(name)' not found.")
                 throw ExitCode.failure
            }
            
            // Apply to global settings in the Unified Config
            // This replaces the old logic of writing to separate config file
            config.activeVaultName = vault.name
            config.settings.defaultEndpoint = vault.endpoint
            config.settings.defaultAccessKey = vault.accessKey
            config.settings.defaultSecretKey = vault.secretKey
            config.settings.defaultRegion = vault.region
            config.settings.defaultBucket = vault.bucket
            
            try StorageService.save(config, mnemonic: mnemonic)
            print("✅ Vault '\(name)' selected. Global settings updated.")
        }
    }
}
