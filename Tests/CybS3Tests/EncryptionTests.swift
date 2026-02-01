import XCTest
import Crypto
@testable import CybS3Lib

final class EncryptionTests: XCTestCase {
    
    // MARK: - Test Fixtures
    
    let validMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".components(separatedBy: " ")
    let validMnemonic2 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent".components(separatedBy: " ")
    
    // MARK: - Key Derivation Tests
    
    func testDeriveKey() throws {
        let key = try Encryption.deriveKey(mnemonic: validMnemonic)
        
        // Key should be 32 bytes (256 bits)
        XCTAssertEqual(key.bitCount, 256)
        
        // Consistent derivation check
        let key2 = try Encryption.deriveKey(mnemonic: validMnemonic)
        XCTAssertEqual(key, key2)
        
        // Different mnemonic -> different key
        let key3 = try Encryption.deriveKey(mnemonic: validMnemonic2)
        XCTAssertNotEqual(key, key3)
    }
    
    func testDeriveKeyProduces256BitKey() throws {
        let key = try Encryption.deriveKey(mnemonic: validMnemonic)
        
        // Verify key is exactly 256 bits (32 bytes)
        XCTAssertEqual(key.bitCount, 256)
        
        // Verify key data length
        let keyData = key.withUnsafeBytes { Data($0) }
        XCTAssertEqual(keyData.count, 32)
    }
    
    func testDeriveKeyIsDeterministic() throws {
        // Derive the same key multiple times
        var keys: [SymmetricKey] = []
        for _ in 1...5 {
            let key = try Encryption.deriveKey(mnemonic: validMnemonic)
            keys.append(key)
        }
        
        // All keys should be identical
        let firstKey = keys[0]
        for key in keys.dropFirst() {
            XCTAssertEqual(key, firstKey)
        }
    }
    
    func testDeriveKeyWithDifferentMnemonicsProducesDifferentKeys() throws {
        let mnemonics = [
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        ].map { $0.components(separatedBy: " ") }
        
        var keys: [SymmetricKey] = []
        for mnemonic in mnemonics {
            let key = try Encryption.deriveKey(mnemonic: mnemonic)
            keys.append(key)
        }
        
        // All keys should be unique
        for i in 0..<keys.count {
            for j in (i+1)..<keys.count {
                XCTAssertNotEqual(keys[i], keys[j], "Keys for different mnemonics should be different")
            }
        }
    }
    
    // MARK: - Encryption Tests
    
    func testEncryptionAndDecryption() throws {
        let key = try Encryption.deriveKey(mnemonic: validMnemonic)
        
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
    
    func testEncryptionWithEmptyData() throws {
        let key = try Encryption.deriveKey(mnemonic: validMnemonic)
        let emptyData = Data()
        
        // Encrypt empty data
        let ciphertext = try Encryption.encrypt(data: emptyData, key: key)
        
        // Ciphertext should contain nonce + tag (at minimum 28 bytes)
        XCTAssertGreaterThan(ciphertext.count, 0)
        
        // Decrypt
        let decrypted = try Encryption.decrypt(data: ciphertext, key: key)
        XCTAssertEqual(decrypted, emptyData)
        XCTAssertEqual(decrypted.count, 0)
    }
    
    func testEncryptionWithSingleByte() throws {
        let key = try Encryption.deriveKey(mnemonic: validMnemonic)
        let singleByte = Data([0x42])
        
        let ciphertext = try Encryption.encrypt(data: singleByte, key: key)
        let decrypted = try Encryption.decrypt(data: ciphertext, key: key)
        
        XCTAssertEqual(decrypted, singleByte)
    }
    
    func testEncryptionWithLargeData() throws {
        let key = try Encryption.deriveKey(mnemonic: validMnemonic)
        
        // 1MB of random-ish data
        let largeData = Data(repeating: 0xAB, count: 1024 * 1024)
        
        let ciphertext = try Encryption.encrypt(data: largeData, key: key)
        let decrypted = try Encryption.decrypt(data: ciphertext, key: key)
        
        XCTAssertEqual(decrypted, largeData)
    }
    
    func testEncryptionProducesUniqueNonce() throws {
        let key = try Encryption.deriveKey(mnemonic: validMnemonic)
        let plaintext = "Same plaintext".data(using: .utf8)!
        
        // Encrypt the same plaintext multiple times
        var ciphertexts: [Data] = []
        for _ in 1...10 {
            let ciphertext = try Encryption.encrypt(data: plaintext, key: key)
            ciphertexts.append(ciphertext)
        }
        
        // Each ciphertext should be unique due to random nonce
        for i in 0..<ciphertexts.count {
            for j in (i+1)..<ciphertexts.count {
                XCTAssertNotEqual(ciphertexts[i], ciphertexts[j], 
                    "Each encryption should produce unique ciphertext due to random nonce")
            }
        }
    }
    
    func testEncryptionCiphertextIsLargerThanPlaintext() throws {
        let key = try Encryption.deriveKey(mnemonic: validMnemonic)
        let plaintext = "Test data".data(using: .utf8)!
        
        let ciphertext = try Encryption.encrypt(data: plaintext, key: key)
        
        // AES-GCM adds: 12-byte nonce + 16-byte tag = 28 bytes overhead
        XCTAssertEqual(ciphertext.count, plaintext.count + 28)
    }
    
    func testEncryptionWithBinaryData() throws {
        let key = try Encryption.deriveKey(mnemonic: validMnemonic)
        
        // Create binary data with all byte values
        var binaryData = Data()
        for byte: UInt8 in 0...255 {
            binaryData.append(byte)
        }
        
        let ciphertext = try Encryption.encrypt(data: binaryData, key: key)
        let decrypted = try Encryption.decrypt(data: ciphertext, key: key)
        
        XCTAssertEqual(decrypted, binaryData)
    }
    
    func testEncryptionWithUnicodeText() throws {
        let key = try Encryption.deriveKey(mnemonic: validMnemonic)
        
        let unicodeText = "Hello 你好 مرحبا שלום 🎉🚀💻"
        let plaintext = unicodeText.data(using: .utf8)!
        
        let ciphertext = try Encryption.encrypt(data: plaintext, key: key)
        let decrypted = try Encryption.decrypt(data: ciphertext, key: key)
        
        XCTAssertEqual(String(data: decrypted, encoding: .utf8), unicodeText)
    }
    
    // MARK: - Decryption Failure Tests
    
    func testDecryptionWithWrongKeyFails() throws {
        let key1 = try Encryption.deriveKey(mnemonic: validMnemonic)
        let key2 = try Encryption.deriveKey(mnemonic: validMnemonic2)
        
        let plaintext = "Sensitive Data".data(using: .utf8)!
        let ciphertext = try Encryption.encrypt(data: plaintext, key: key1)
        
        XCTAssertThrowsError(try Encryption.decrypt(data: ciphertext, key: key2)) { error in
            // Expected failure (e.g. CryptoKit Authentication Failure)
        }
    }
    
    func testDecryptionWithTruncatedDataFails() throws {
        let key = try Encryption.deriveKey(mnemonic: validMnemonic)
        let plaintext = "Test message".data(using: .utf8)!
        
        let ciphertext = try Encryption.encrypt(data: plaintext, key: key)
        
        // Truncate the ciphertext (remove last 10 bytes)
        let truncated = ciphertext.prefix(ciphertext.count - 10)
        
        XCTAssertThrowsError(try Encryption.decrypt(data: Data(truncated), key: key))
    }
    
    func testDecryptionWithCorruptedDataFails() throws {
        let key = try Encryption.deriveKey(mnemonic: validMnemonic)
        let plaintext = "Test message".data(using: .utf8)!
        
        var ciphertext = try Encryption.encrypt(data: plaintext, key: key)
        
        // Corrupt a byte in the middle
        let midpoint = ciphertext.count / 2
        ciphertext[midpoint] ^= 0xFF
        
        XCTAssertThrowsError(try Encryption.decrypt(data: ciphertext, key: key))
    }
    
    func testDecryptionWithTooShortDataFails() throws {
        let key = try Encryption.deriveKey(mnemonic: validMnemonic)
        
        // Data too short to contain valid AES-GCM sealed box (needs at least 28 bytes)
        let shortData = Data([1, 2, 3, 4, 5])
        
        XCTAssertThrowsError(try Encryption.decrypt(data: shortData, key: key))
    }
    
    func testDecryptionWithEmptyCiphertextFails() throws {
        let key = try Encryption.deriveKey(mnemonic: validMnemonic)
        let emptyData = Data()
        
        XCTAssertThrowsError(try Encryption.decrypt(data: emptyData, key: key))
    }
    
    // MARK: - EncryptionError Tests
    
    func testEncryptionErrorDescriptions() {
        let errors: [EncryptionError] = [
            .encryptionFailed,
            .decryptionFailed,
            .invalidKey,
            .keyDerivationFailed(reason: "Invalid mnemonic checksum")
        ]
        
        for error in errors {
            XCTAssertNotNil(error.errorDescription)
            XCTAssertFalse(error.errorDescription!.isEmpty)
        }
    }
    
    func testKeyDerivationFailedErrorContainsReason() {
        let reason = "PBKDF2 iteration count too low"
        let error = EncryptionError.keyDerivationFailed(reason: reason)
        
        XCTAssertTrue(error.errorDescription!.contains(reason))
    }
    
    // MARK: - Performance Tests
    
    func testKeyDerivationPerformance() throws {
        measure {
            _ = try? Encryption.deriveKey(mnemonic: validMnemonic)
        }
    }
    
    func testEncryptionPerformance() throws {
        let key = try Encryption.deriveKey(mnemonic: validMnemonic)
        let data = Data(repeating: 0xAB, count: 1024 * 1024) // 1MB
        
        measure {
            _ = try? Encryption.encrypt(data: data, key: key)
        }
    }
    
    func testDecryptionPerformance() throws {
        let key = try Encryption.deriveKey(mnemonic: validMnemonic)
        let data = Data(repeating: 0xAB, count: 1024 * 1024) // 1MB
        let ciphertext = try Encryption.encrypt(data: data, key: key)
        
        measure {
            _ = try? Encryption.decrypt(data: ciphertext, key: key)
        }
    }
}
