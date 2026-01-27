import Foundation
import Security

public enum KeychainError: Error {
    case duplicateEntry
    case unknown(OSStatus)
    case itemNotFound
}

public struct KeychainService {
    private static let serviceName = "cybs3-cli"
    private static let accountName = "default"

    /// Saves the mnemonic to the Keychain.
    public static func save(mnemonic: [String]) throws {
        let mnemonicString = mnemonic.joined(separator: " ")
        guard let data = mnemonicString.data(using: .utf8) else { return }

        // Create query
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountName,
            kSecValueData as String: data
        ]

        // Delete any existing item
        SecItemDelete(query as CFDictionary)

        // Add new item
        let status = SecItemAdd(query as CFDictionary, nil)
        
        guard status == errSecSuccess else {
            throw KeychainError.unknown(status)
        }
    }

    /// Loads the mnemonic from the Keychain.
    public static func load() -> [String]? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountName,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)

        if status == errSecSuccess, let data = dataTypeRef as? Data, let mnemonicString = String(data: data, encoding: .utf8) {
            return mnemonicString.components(separatedBy: " ")
        }
        return nil
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
