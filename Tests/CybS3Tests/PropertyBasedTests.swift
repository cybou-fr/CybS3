import XCTest
import SwiftCheck
import Crypto
@testable import CybS3Lib

extension Data: Arbitrary {
    /// Generate arbitrary Data for property testing.
    public static var arbitrary: Gen<Data> {
        return [UInt8].arbitrary.map { Data($0) }
    }
}

final class PropertyBasedTests: XCTestCase {
    
    // MARK: - Encryption Properties
    
    func testEncryptionDecryptsCorrectly() {
        property("Encryption roundtrip preserves data") <- forAll { (data: Data) in
            // Skip empty data as it's not meaningful for encryption
            guard !data.isEmpty else { return true }
            
            let key = SymmetricKey(size: .bits256)
            let encrypted = try? Encryption.encrypt(data: data, key: key)
            let decrypted = encrypted.flatMap { try? Encryption.decrypt(data: $0, key: key) }
            return decrypted == data
        }
    }
    
    func testEncryptionIsDeterministic() {
        property("Same data and key produce same ciphertext") <- forAll { (data: Data) in
            guard !data.isEmpty else { return true }
            
            let key = SymmetricKey(size: .bits256)
            let encrypted1 = try? Encryption.encrypt(data: data, key: key)
            let encrypted2 = try? Encryption.encrypt(data: data, key: key)
            return encrypted1 == encrypted2
        }
    }
    
    func testDifferentKeysProduceDifferentCiphertext() {
        property("Different keys produce different ciphertext") <- forAll { (data: Data) in
            guard !data.isEmpty else { return true }
            
            let key1 = SymmetricKey(size: .bits256)
            let key2 = SymmetricKey(size: .bits256)
            let encrypted1 = try? Encryption.encrypt(data: data, key: key1)
            let encrypted2 = try? Encryption.encrypt(data: data, key: key2)
            return encrypted1 != encrypted2
        }
    }
    
    func testKeyDerivationIsDeterministic() {
        property("Key derivation is deterministic for same mnemonic") <- forAll { (words: [String]) in
            // Filter to valid mnemonic lengths (12, 15, 18, 21, 24 words)
            let validLengths = [12, 15, 18, 21, 24]
            guard validLengths.contains(words.count) else { return true }
            
            // Ensure all words are valid BIP39 words (simplified check)
            let validWords = words.filter { !$0.isEmpty && $0.count > 2 }
            guard validWords.count == words.count else { return true }
            
            let key1 = try? Encryption.deriveKey(mnemonic: words)
            let key2 = try? Encryption.deriveKey(mnemonic: words)
            return key1 == key2
        }
    }
    
    func testKeyDerivationProducesValidKeys() {
        property("Key derivation produces 256-bit keys") <- forAll { (words: [String]) in
            let validLengths = [12, 15, 18, 21, 24]
            guard validLengths.contains(words.count) else { return true }
            
            let validWords = words.filter { !$0.isEmpty && $0.count > 2 }
            guard validWords.count == words.count else { return true }
            
            let key = try? Encryption.deriveKey(mnemonic: words)
            return key?.bitCount == 256
        }
    }
    
    // MARK: - Data Transformation Properties
    
    func testDataHexConversionIsReversible() {
        property("Data hex conversion is reversible") <- forAll { (data: Data) in
            let hex = data.hexString
            let backToData = Data(hexString: hex)
            return backToData == data
        }
    }
    
    func testSHA256IsDeterministic() {
        property("SHA256 hash is deterministic") <- forAll { (data: Data) in
            let hash1 = data.sha256()
            let hash2 = data.sha256()
            return hash1 == hash2
        }
    }
    
    func testSHA256ProducesValidHex() {
        property("SHA256 produces valid hex string") <- forAll { (data: Data) in
            let hash = data.sha256()
            // SHA256 should produce 64 character hex string
            return hash.count == 64 && hash.allSatisfy { $0.isHexDigit }
        }
    }
    
    // MARK: - Retry Policy Properties
    
    func testRetryPolicyDelaysIncrease() {
        property("Retry policy delays increase exponentially") <- forAll { (attempts: Int) in
            let policy = RetryPolicy(maxAttempts: 5, baseDelay: 1.0, maxDelay: 100.0)
            
            guard attempts > 0 && attempts < 10 else { return true }
            
            let delay1 = policy.delay(for: attempts - 1)
            let delay2 = policy.delay(for: attempts)
            
            return delay2 >= delay1
        }
    }
    
    func testRetryPolicyRespectsMaxDelay() {
        property("Retry policy respects maximum delay") <- forAll { (attempt: Int) in
            let maxDelay: TimeInterval = 30.0
            let policy = RetryPolicy(maxAttempts: 10, baseDelay: 1.0, maxDelay: maxDelay)
            
            guard attempt >= 0 && attempt < 20 else { return true }
            
            let delay = policy.delay(for: attempt)
            return delay <= maxDelay
        }
    }
    
    // MARK: - Circuit Breaker Properties
    
    func testCircuitBreakerStateTransitions() async {
        let circuitBreaker = CircuitBreaker(threshold: 3, timeout: 60.0)
        
        // Initially closed
        let initialState = await circuitBreaker.state
        let initialFailureCount = await circuitBreaker.currentFailureCount
        XCTAssertEqual(initialState, .closed)
        XCTAssertEqual(initialFailureCount, 0)
        
        // Record failures by executing failing operations
        for _ in 0..<3 {
            do {
                try await circuitBreaker.execute {
                    throw NSError(domain: "test", code: 1, userInfo: nil)
                }
            } catch {
                // Expected
            }
        }
        
        // Should be open after threshold
        let finalState = await circuitBreaker.state
        let finalFailureCount = await circuitBreaker.currentFailureCount
        XCTAssertEqual(finalState, .open)
        XCTAssertEqual(finalFailureCount, 3)
    }
}

// MARK: - Custom Generators

// MARK: - Extensions for Testing

extension Data {
    /// Initialize Data from hex string.
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var index = hexString.startIndex
        for _ in 0..<len {
            let nextIndex = hexString.index(index, offsetBy: 2)
            if let byte = UInt8(hexString[index..<nextIndex], radix: 16) {
                data.append(byte)
            } else {
                return nil
            }
            index = nextIndex
        }
        self = data
    }
}