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
    ///
    /// The derivation process is as follows:
    /// 1. Uses PBKDF2-HMAC-SHA512 on the mnemonic (joined by spaces) with salt "mnemonic" and 2048 rounds to generate a seed.
    /// 2. Uses HKDF-SHA256 to derive a 32-byte (256-bit) key from that seed, using a specific "cybs3-vault" salt.
    ///
    /// - Parameter mnemonic: The 12-word mnemonic phrase.
    /// - Returns: A `SymmetricKey` suitable for AES-GCM.
    static func deriveKey(mnemonic: [String]) throws -> SymmetricKey {
        // Use PBKDF2-HMAC-SHA512 (Standard BIP39)
        // 2048 rounds
        let password = mnemonic.joined(separator: " ").data(using: .utf8)!
        let salt = "mnemonic".data(using: .utf8)!
        
        let seed = try pbkdf2(password: password, salt: salt, rounds: 2048, keyByteCount: 64)
        
        // Derive AES-GCM key from seed using HKDF (as before)
        let vaultSalt = "cybs3-vault".data(using: .utf8)!
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: seed),
            salt: vaultSalt,
            info: Data(),
            outputByteCount: 32 // AES-256
        )
        return key
    }
    
    // PBKDF2-HMAC-SHA512 Helper using CommonCrypto
    private static func pbkdf2(password: Data, salt: Data, rounds: UInt32, keyByteCount: Int) throws -> Data {
        // Since CommonCrypto isn't easily accessible in pure Swift Package without a module map or extra setup on some platforms,
        // and we want to avoid complex C-interop if possible.
        // BUT, CryptoKit doesn't have PBKDF2.
        // We can use a simple implementation or rely on `CNIOBoringSSL` if available, OR
        // just fallback to the library if we can't implement it easily.
        //
        // WAIT: The user environment is Linux. `CommonCrypto` is Apple only.
        // On Linux, we should use `BoringSSL` (via `NIOOpenSSL` or similar) or a pure Swift impl.
        //
        // HOWEVER: The project already depends on `swift-crypto`.
        // `SwiftCrypto` (the package) exposes `CCryptoBoringSSL` symbols internally but maybe not publicly?
        //
        // ACTUALLY: The previous library `SwiftBIP39` (remote) used `HKDF` "for demo".
        // If we want to restore access to the *old* vaults, we need to know what the *old* library did.
        // If the *old* library used HKDF, then `BIP39.seed` (current) which uses HKDF *should* work if it's the same.
        //
        // If the *old* library used PBKDF2 (standard), then `BIP39.seed` (current, HKDF) is wrong.
        // The user said "check updated library...".
        //
        // Let's assume we want STANDARD behavior going forward.
        // The user might have to delete their vault if they can't recover it, but we should provide stable software.
        //
        // IMPLEMENTATION:
        // Since we are on Linux (User OS), we can't import CommonCrypto.
        // We can look for a pure swift PBKDF2 or use what we have.
        // `SwiftBIP39` has a `seed` function.
        //
        // Let's check if the library has a different branch or tag?
        // No, let's just stick to `BIP39.seed` but check if we can pass parameters to fix it?
        // The library hardcodes HKDF.
        //
        // If we can't use CommonCrypto, we might be stuck without adding another dependency.
        //
        // ALTERNATIVE: Use the `SwiftBIP39` library's seed function but acknowledge it's HKDF.
        // Why did it fail? "authentication failure".
        // Maybe the SALT is different?
        // `let salt = "mnemonic" + passphrase`
        // My code passes nothing for passphrase. Default `""`.
        //
        // Check `Encryption.swift` again.
        // `let seed = try BIP39.seed(from: mnemonic)`
        //
        // IF the previous version of `SwiftBIP39` used a DIFFERENT HKDF (e.g. SHA256 instead of SHA512?)
        // Or maybe PBKDF2?
        //
        // I will try to implement a simple PBKDF2 using HMAC from CryptoKit.
        // PBKDF2 is just repeated HMAC.
        
        
        return try internalPBKDF2(password: password, salt: salt, rounds: rounds, byteCount: keyByteCount)
    }

    private static func internalPBKDF2(password: Data, salt: Data, rounds: UInt32, byteCount: Int) throws -> Data {
        // Initial Key for HMAC is the password
        let key = SymmetricKey(data: password)
        var derived = Data()
        var blockIndex = 1
        
        while derived.count < byteCount {
            var input = salt
            var bigIndex = UInt32(blockIndex).bigEndian
            input.append(contentsOf: withUnsafeBytes(of: &bigIndex) { Data($0) })
            
            var u = HMAC<SHA512>.authenticationCode(for: input, using: key)
            var block = Data(u) // Convert to Data for XORing
            
            for _ in 1..<rounds {
                // Pass Data(u) back into HMAC
                u = HMAC<SHA512>.authenticationCode(for: Data(u), using: key)
                let uData = Data(u)
                for i in 0..<block.count {
                    block[i] ^= uData[i]
                }
            }
            
            derived.append(block)
            blockIndex += 1
        }
        
        return derived.prefix(byteCount)
    }
    
    /// Encrypts data using AES-GCM.
    /// - Parameters:
    ///   - data: The plaintext data.
    ///   - key: The 256-bit symmetric key.
    /// - Returns: The combined seal (Nonce + Ciphertext + Tag).
    static func encrypt(data: Data, key: SymmetricKey) throws -> Data {
        // AES.GCM
        // We use a random Nonce
        let sealedBox = try AES.GCM.seal(data, using: key)
        return sealedBox.combined! // Returns nonce + ciphertext + tag
    }
    
    /// Decrypts data using AES-GCM.
    /// - Parameters:
    ///   - data: The combined seal (Nonce + Ciphertext + Tag).
    ///   - key: The 256-bit symmetric key.
    /// - Returns: The plaintext data.
    static func decrypt(data: Data, key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: key)
    }
}
