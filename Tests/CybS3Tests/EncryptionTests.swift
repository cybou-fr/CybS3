import XCTest
import Crypto
@testable import CybS3Lib

final class EncryptionTests: XCTestCase {
    
    func testDeriveKey() throws {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".components(separatedBy: " ")
        let key = try Encryption.deriveKey(mnemonic: mnemonic)
        
        // Key should be 32 bytes (256 bits)
        XCTAssertEqual(key.bitCount, 256)
        
        // Consistent derivation check
        let key2 = try Encryption.deriveKey(mnemonic: mnemonic)
        XCTAssertEqual(key, key2)
        
        // Different mnemonic -> different key
        let mnemonic2 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent".components(separatedBy: " ")
        let key3 = try Encryption.deriveKey(mnemonic: mnemonic2)
        XCTAssertNotEqual(key, key3)
    }
    
    func testEncryptionAndDecryption() throws {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".components(separatedBy: " ")
        let key = try Encryption.deriveKey(mnemonic: mnemonic)
        
        let plaintext = "Hello, World! This is a test.".data(using: .utf8)!
        
        // Encrypt
        let ciphertext = try Encryption.encrypt(data: plaintext, key: key)
        XCTAssertNotEqual(ciphertext, plaintext)
        
        // Decrypt
        let decrypted = try Encryption.decrypt(data: ciphertext, key: key)
        XCTAssertEqual(decrypted, plaintext)
        
        // Verify Round Trip String
        let decryptedString = String(data: decrypted, encoding: .utf8)
        XCTAssertEqual(decryptedString, "Hello, World! This is a test.")
    }
    
    func testDecryptionWithWrongKeyFails() throws {
        let mnemonic1 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".components(separatedBy: " ")
        let key1 = try Encryption.deriveKey(mnemonic: mnemonic1)
        
        let mnemonic2 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent".components(separatedBy: " ")
        let key2 = try Encryption.deriveKey(mnemonic: mnemonic2)
        
        let plaintext = "Sensitive Data".data(using: .utf8)!
        let ciphertext = try Encryption.encrypt(data: plaintext, key: key1)
        
        XCTAssertThrowsError(try Encryption.decrypt(data: ciphertext, key: key2)) { error in
            // Expected failure (e.g. CryptoKit Authentication Failure)
            // CryptoKit throws CryptoKitError.authenticationFailure usually
        }
    }
}
