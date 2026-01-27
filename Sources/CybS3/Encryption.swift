import Foundation
import Crypto
import SwiftBIP39

enum EncryptionError: Error {
    case encryptionFailed
    case decryptionFailed
    case invalidKey
}

struct Encryption {
    /// Derives a 256-bit SymmetricKey from the mnemonic phrase.
    /// We use the seed from BIP39 (512 bits usually, or 256 bits depending on BIP39 impl).
    /// BIP39.seed() returns Data. We can use HKDF to derive a specific AES-GCM key from that seed.
    static func deriveKey(mnemonic: [String]) -> SymmetricKey {
        let seed = BIP39.seed(from: mnemonic)
        let salt = "cybs3-vault".data(using: .utf8)!
        
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: seed),
            salt: salt,
            info: Data(),
            outputByteCount: 32 // AES-256
        )
        return key
    }
    
    static func encrypt(data: Data, key: SymmetricKey) throws -> Data {
        // AES.GCM
        // We use a random Nonce
        let sealedBox = try AES.GCM.seal(data, using: key)
        return sealedBox.combined! // Returns nonce + ciphertext + tag
    }
    
    static func decrypt(data: Data, key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: key)
    }
}
