import Foundation
import Crypto
#if os(macOS)
import Security
#endif

/// Enhanced key derivation utilities with additional security features.
public struct EnhancedKeyDerivation {
    /// Derives a 256-bit SymmetricKey from the mnemonic phrase with optional additional entropy.
    ///
    /// The derivation process is as follows:
    /// 1. Uses PBKDF2-HMAC-SHA512 on the mnemonic (joined by spaces) with salt "mnemonic" and 2048 rounds to generate a seed.
    /// 2. Uses HKDF-SHA256 to derive a 32-byte (256-bit) key from that seed, using a specific "cybs3-enhanced" salt.
    /// 3. If additional salt is provided, applies another HKDF layer for extra entropy.
    ///
    /// - Parameters:
    ///   - mnemonic: The 12-word mnemonic phrase.
    ///   - salt: Optional additional entropy to mix into the key derivation.
    /// - Returns: A `SymmetricKey` suitable for AES-GCM.
    public static func deriveKey(mnemonic: [String], salt: Data? = nil) throws -> SymmetricKey {
        let baseKey = try Encryption.deriveKey(mnemonic: mnemonic)
        
        if let additionalSalt = salt {
            return HKDF<SHA256>.deriveKey(
                inputKeyMaterial: baseKey,
                salt: additionalSalt,
                info: "cybs3-enhanced".data(using: .utf8)!,
                outputByteCount: 32
            )
        }
        return baseKey
    }
    
    /// Generates additional entropy from system sources for key derivation.
    ///
    /// - Returns: A Data object containing system entropy.
    public static func generateSystemEntropy() -> Data {
        var entropy = Data()
        
        // Add current timestamp
        var timestamp = UInt64(Date().timeIntervalSince1970 * 1000000) // microseconds
        entropy.append(contentsOf: withUnsafeBytes(of: &timestamp) { Data($0) })
        
        // Add process ID
        #if os(macOS)
        var pid = UInt32(getpid())
        #else
        var pid = UInt32(getpid())
        #endif
        entropy.append(contentsOf: withUnsafeBytes(of: &pid) { Data($0) })
        
        // Add some random bytes
        var randomBytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
        entropy.append(contentsOf: randomBytes)
        
        return entropy
    }
    
    /// Derives a key with automatic system entropy inclusion.
    ///
    /// - Parameter mnemonic: The 12-word mnemonic phrase.
    /// - Returns: A `SymmetricKey` with enhanced entropy.
    public static func deriveKeyWithEntropy(mnemonic: [String]) throws -> SymmetricKey {
        let systemEntropy = generateSystemEntropy()
        return try deriveKey(mnemonic: mnemonic, salt: systemEntropy)
    }
}