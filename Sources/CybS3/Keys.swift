import Foundation
import ArgumentParser
import SwiftBIP39

extension CybS3 {
    struct Keys: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "keys",
            abstract: "Manage encryption keys and mnemonics",
            subcommands: [
                Create.self,
                Validate.self
            ]
        )
    }
}

extension CybS3.Keys {
    struct Create: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "create",
            abstract: "Generate a new 12-word mnemonic phrase"
        )
        
        func run() async throws {
            do {
                let mnemonic = try BIP39.generateMnemonic()
                print("Your new mnemonic phrase (KEEP THIS SAFE!):")
                print("------------------------------------------------")
                print(mnemonic.joined(separator: " "))
                print("------------------------------------------------")
            } catch {
                print("Error generating mnemonic: \(error)")
                throw ExitCode.failure
            }
        }
    }
    
    struct Validate: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "validate",
            abstract: "Validate a mnemonic phrase"
        )
        
        @Argument(help: "The mnemonic phrase to validate (12 words)")
        var words: [String]
        
        func run() async throws {
            do {
                try BIP39.validate(mnemonic: words)
                print("✅ Mnemonic is valid.")
            } catch BIP39.Error.invalidWordCount {
                print("❌ Invalid word count. Expected 12 words.")
                throw ExitCode.failure
            } catch BIP39.Error.invalidWord(let word) {
                print("❌ Invalid word found: '\(word)' appears to be not in the wordlist.")
                throw ExitCode.failure
            } catch BIP39.Error.invalidChecksum {
                print("❌ Invalid checksum. The phrase is not valid.")
                throw ExitCode.failure
            } catch {
                print("❌ Error: \(error)")
                throw ExitCode.failure
            }
        }
    }
}
