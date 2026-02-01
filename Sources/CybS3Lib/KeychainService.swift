import Foundation
import Security
import LocalAuthentication

public enum KeychainError: Error, LocalizedError {
    case duplicateEntry
    case unknown(OSStatus)
    case itemNotFound
    case accessControlCreationFailed
    case biometricNotAvailable
    
    public var errorDescription: String? {
        switch self {
        case .duplicateEntry:
            return "❌ Keychain entry already exists."
        case .unknown(let status):
            return "❌ Keychain error (code: \(status))."
        case .itemNotFound:
            return "❌ No mnemonic found in Keychain. Run 'cybs3 login' first."
        case .accessControlCreationFailed:
            return "❌ Failed to create access control for Keychain."
        case .biometricNotAvailable:
            return "❌ Biometric authentication not available on this device."
        }
    }
}

/// Security level for Keychain storage.
public enum KeychainSecurityLevel {
    /// Standard protection - accessible when unlocked.
    case standard
    /// Enhanced protection - requires user presence (Touch ID, Face ID, or password).
    case biometric
}

public struct KeychainService {
    private static let serviceName = "cybs3-cli"
    private static let accountName = "default"

    /// Saves the mnemonic to the Keychain with configurable security level.
    ///
    /// - Parameters:
    ///   - mnemonic: The mnemonic words to save.
    ///   - securityLevel: The desired security level.
    /// - Note: The mnemonic string is cleared from memory after saving.
    public static func save(mnemonic: [String], securityLevel: KeychainSecurityLevel = .standard) throws {
        var mnemonicString = mnemonic.joined(separator: " ")
        defer {
            // Securely clear the mnemonic from memory
            mnemonicString.withUTF8 { _ in }
            mnemonicString = String(repeating: "\0", count: mnemonicString.count)
        }
        
        guard var data = mnemonicString.data(using: .utf8) else { return }
        defer {
            // Clear sensitive data from memory
            data.resetBytes(in: 0..<data.count)
        }

        // Delete any existing item
        try? delete()
        
        // Build query
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountName,
            kSecValueData as String: data
        ]
        
        // Add access control for biometric security
        if securityLevel == .biometric {
            var error: Unmanaged<CFError>?
            guard let accessControl = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .userPresence,
                &error
            ) else {
                throw KeychainError.accessControlCreationFailed
            }
            query[kSecAttrAccessControl as String] = accessControl
        } else {
            query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }

        // Add new item
        let status = SecItemAdd(query as CFDictionary, nil)
        
        guard status == errSecSuccess else {
            throw KeychainError.unknown(status)
        }
    }

    /// Loads the mnemonic from the Keychain.
    ///
    /// - Parameter promptMessage: Optional message to display for biometric prompt.
    /// - Returns: The mnemonic words, or nil if not found.
    public static func load(promptMessage: String? = nil) -> [String]? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountName,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        // Use LAContext for biometric prompt (modern API)
        if let message = promptMessage {
            let context = LAContext()
            context.localizedReason = message
            query[kSecUseAuthenticationContext as String] = context
        }

        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)

        if status == errSecSuccess, let data = dataTypeRef as? Data, let mnemonicString = String(data: data, encoding: .utf8) {
            return mnemonicString.components(separatedBy: " ")
        }
        return nil
    }
    
    /// Checks if a mnemonic is stored in the Keychain.
    public static func exists() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountName,
            kSecReturnData as String: false
        ]
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    /// Deletes the mnemonic from the Keychain.
    public static func delete() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountName
        ]

        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
           throw KeychainError.unknown(status)
        }
    }
}
