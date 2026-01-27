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
                Validate.self,
                Rotate.self
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
                let mnemonic = try BIP39.generateMnemonic(wordCount: .twelve, language: .english)
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
                try BIP39.validate(mnemonic: words, language: .english)
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
    
    struct Rotate: AsyncParsableCommand {
         static let configuration = CommandConfiguration(
             commandName: "rotate",
             abstract: "Rotate your Mnemonic (Master Key) while preserving data access"
         )
         
         func run() async throws {
             print("Key Rotation Process")
             print("------------------------------------------------")
             print("1. Authenticate with CURRENT Mnemonic")
             
             let oldMnemonic: [String]
             do {
                 oldMnemonic = try InteractionService.promptForMnemonic(purpose: "authenticate (Current Mnemonic)")
             } catch {
                 print("Error: \(error)")
                 throw ExitCode.failure
             }
             
             print("\n2. Enter (or Generate) NEW Mnemonic")
             print("Do you want to (G)enerate a new one or (E)nter one manually? [G/e]")
             let choice = readLine()?.lowercased() ?? "g"
             
             let newMnemonic: [String]
             if choice.starts(with: "e") {
                 do {
                     newMnemonic = try InteractionService.promptForMnemonic(purpose: "set as NEW Mnemonic")
                 } catch {
                     print("Error: \(error)")
                     throw ExitCode.failure
                 }
             } else {
                 do {
                     newMnemonic = try BIP39.generateMnemonic(wordCount: .twelve, language: .english)
                     print("\nYOUR NEW MNEMONIC (WRITE THIS DOWN!):")
                     print("************************************************")
                     print(newMnemonic.joined(separator: " "))
                     print("************************************************")
                     print("\nPress Enter once you have saved it.")
                     _ = readLine()
                 } catch {
                     print("Error generating mnemonic: \(error)")
                     throw ExitCode.failure
                 }
             }
             
             // Verify they have it? (Optional, skipping for now for brevity but recommended in real app)
             
             do {
                 try StorageService.rotateKey(oldMnemonic: oldMnemonic, newMnemonic: newMnemonic)
                 print("\n✅ Key Rotation Successful.")
                 print("You MUST use your NEW mnemonic for all future operations.")
             } catch {
                 print("Error rotating key: \(error)")
                 throw ExitCode.failure
             }
         }
     }
}
