import Foundation
#if os(macOS)
import Darwin
#else
import Glibc
#endif

// MARK: - CLI Error Wrapper

/// A unified error type for CLI operations that provides consistent, user-friendly error messages.
public enum CLIError: Error, LocalizedError {
    // MARK: - Configuration Errors
    case configurationNotFound
    case configurationCorrupted(underlying: Error?)
    case configurationMigrationFailed(reason: String)
    
    // MARK: - Authentication Errors
    case authenticationRequired
    case invalidCredentials(service: String)
    case keychainAccessFailed(operation: String, underlying: Error?)
    
    // MARK: - Mnemonic Errors
    case mnemonicRequired
    case invalidMnemonic(reason: String)
    case mnemonicMismatch
    
    // MARK: - Vault Errors
    case vaultNotFound(name: String)
    case vaultAlreadyExists(name: String)
    case noVaultsConfigured
    
    // MARK: - S3 Operation Errors
    case bucketRequired
    case bucketNotFound(name: String)
    case bucketNotEmpty(name: String)
    case objectNotFound(key: String)
    case accessDenied(resource: String?)
    case networkError(underlying: Error)
    case invalidEndpoint(url: String)
    
    // MARK: - File System Errors
    case fileNotFound(path: String)
    case fileAccessDenied(path: String)
    case fileWriteFailed(path: String, underlying: Error?)
    case directoryCreationFailed(path: String)
    
    // MARK: - Encryption Errors
    case encryptionFailed(reason: String?)
    case decryptionFailed(reason: String?)
    case keyDerivationFailed
    
    // MARK: - User Interaction Errors
    case userCancelled
    case invalidInput(expected: String)
    case operationAborted(reason: String)
    
    // MARK: - Generic Errors
    case internalError(message: String)
    case unknown(underlying: Error)
    
    // MARK: - LocalizedError Conformance
    
    public var errorDescription: String? {
        switch self {
        // Configuration
        case .configurationNotFound:
            return "Configuration not found. Run 'cybs3 login' to create one."
        case .configurationCorrupted(let underlying):
            var msg = "Configuration file is corrupted or unreadable."
            if let underlying = underlying {
                msg += "\n   Details: \(underlying.localizedDescription)"
            }
            return msg
        case .configurationMigrationFailed(let reason):
            return "Failed to migrate configuration: \(reason)"
            
        // Authentication
        case .authenticationRequired:
            return "Authentication required. Run 'cybs3 login' to authenticate."
        case .invalidCredentials(let service):
            return "Invalid credentials for \(service). Please check your access key and secret key."
        case .keychainAccessFailed(let operation, let underlying):
            var msg = "Keychain \(operation) failed."
            if let underlying = underlying {
                msg += "\n   Details: \(underlying.localizedDescription)"
            }
            return msg
            
        // Mnemonic
        case .mnemonicRequired:
            return "Mnemonic is required. Run 'cybs3 keys create' to generate one."
        case .invalidMnemonic(let reason):
            return "Invalid mnemonic: \(reason)"
        case .mnemonicMismatch:
            return "The provided mnemonic does not match the stored configuration."
            
        // Vault
        case .vaultNotFound(let name):
            return "Vault '\(name)' not found. Run 'cybs3 vaults list' to see available vaults."
        case .vaultAlreadyExists(let name):
            return "Vault '\(name)' already exists. Choose a different name."
        case .noVaultsConfigured:
            return "No vaults configured. Run 'cybs3 vaults add --name <name>' to create one."
            
        // S3 Operations
        case .bucketRequired:
            return "Bucket name is required. Use --bucket <name> or set a default with 'cybs3 config --bucket <name>'."
        case .bucketNotFound(let name):
            return "Bucket '\(name)' not found. Verify the bucket name and your permissions."
        case .bucketNotEmpty(let name):
            return "Bucket '\(name)' is not empty. Delete all objects before deleting the bucket."
        case .objectNotFound(let key):
            return "Object '\(key)' not found. Check the key name and bucket."
        case .accessDenied(let resource):
            if let resource = resource {
                return "Access denied to '\(resource)'. Check your credentials and permissions."
            }
            return "Access denied. Check your credentials and bucket policies."
        case .networkError(let underlying):
            return "Network error: \(underlying.localizedDescription)"
        case .invalidEndpoint(let url):
            return "Invalid endpoint URL: '\(url)'. Use format: https://s3.amazonaws.com or s3.region.amazonaws.com"
            
        // File System
        case .fileNotFound(let path):
            return "File not found: \(path)"
        case .fileAccessDenied(let path):
            return "Permission denied: Cannot access '\(path)'."
        case .fileWriteFailed(let path, let underlying):
            var msg = "Failed to write file: \(path)"
            if let underlying = underlying {
                msg += "\n   Details: \(underlying.localizedDescription)"
            }
            return msg
        case .directoryCreationFailed(let path):
            return "Failed to create directory: \(path)"
            
        // Encryption
        case .encryptionFailed(let reason):
            return "Encryption failed" + (reason.map { ": \($0)" } ?? ".")
        case .decryptionFailed(let reason):
            return "Decryption failed" + (reason.map { ": \($0)" } ?? ". The mnemonic may be incorrect or data corrupted.")
        case .keyDerivationFailed:
            return "Failed to derive encryption key from mnemonic."
            
        // User Interaction
        case .userCancelled:
            return "Operation cancelled."
        case .invalidInput(let expected):
            return "Invalid input. Expected: \(expected)"
        case .operationAborted(let reason):
            return "Operation aborted: \(reason)"
            
        // Generic
        case .internalError(let message):
            return "Internal error: \(message)"
        case .unknown(let underlying):
            return "An unexpected error occurred: \(underlying.localizedDescription)"
        }
    }
    
    /// Returns the error symbol for consistent CLI output.
    public var symbol: String {
        switch self {
        case .userCancelled, .operationAborted:
            return "⚠️"
        default:
            return "❌"
        }
    }
    
    /// Returns a formatted error message for CLI output.
    public var formattedMessage: String {
        return "\(symbol) \(errorDescription ?? "Unknown error")"
    }
    
    /// Suggested action for the user to resolve this error.
    public var suggestion: String? {
        switch self {
        case .configurationNotFound, .authenticationRequired:
            return "💡 Run 'cybs3 login' to authenticate."
        case .mnemonicRequired:
            return "💡 Run 'cybs3 keys create' to generate a new mnemonic."
        case .noVaultsConfigured:
            return "💡 Run 'cybs3 vaults add --name <name>' to create a vault."
        case .bucketRequired:
            return "💡 Use --bucket <name> or run 'cybs3 config --bucket <name>' to set a default."
        case .invalidCredentials:
            return "💡 Verify your AWS Access Key and Secret Key are correct."
        case .decryptionFailed:
            return "💡 Ensure you're using the correct mnemonic phrase."
        case .vaultNotFound:
            return "💡 Run 'cybs3 vaults list' to see available vaults."
        default:
            return nil
        }
    }
    
    /// Prints the error with its suggestion to stderr.
    public func printError() {
        let msg = "\(formattedMessage)\n"
        FileHandle.standardError.write(Data(msg.utf8))
        if let suggestion = suggestion {
            let sug = "\(suggestion)\n"
            FileHandle.standardError.write(Data(sug.utf8))
        }
    }
}

// MARK: - Error Conversion Helpers

extension CLIError {
    /// Creates a CLIError from an S3Error.
    public static func from(_ s3Error: S3Error) -> CLIError {
        switch s3Error {
        case .invalidURL:
            return .invalidEndpoint(url: "unknown")
        case .authenticationFailed:
            return .invalidCredentials(service: "S3")
        case .bucketNotFound:
            return .bucketNotFound(name: "unknown")
        case .objectNotFound:
            return .objectNotFound(key: "unknown")
        case .accessDenied(let resource):
            return .accessDenied(resource: resource)
        case .bucketNotEmpty:
            return .bucketNotEmpty(name: "unknown")
        case .requestFailed, .requestFailedLegacy, .invalidResponse, .fileAccessFailed:
            return .unknown(underlying: s3Error)
        }
    }
    
    /// Creates a CLIError from a StorageError.
    public static func from(_ storageError: StorageError) -> CLIError {
        switch storageError {
        case .configNotFound:
            return .configurationNotFound
        case .decryptionFailed:
            return .decryptionFailed(reason: "Invalid mnemonic or corrupted data")
        case .integrityCheckFailed:
            return .configurationCorrupted(underlying: storageError)
        case .unsupportedVersion(let version):
            return .configurationMigrationFailed(reason: "Unsupported version \(version)")
        case .oldVaultsFoundButMigrationFailed:
            return .configurationMigrationFailed(reason: "Legacy vault migration failed")
        }
    }
    
    /// Creates a CLIError from an InteractionError.
    public static func from(_ interactionError: InteractionError) -> CLIError {
        switch interactionError {
        case .mnemonicRequired:
            return .mnemonicRequired
        case .bucketRequired:
            return .bucketRequired
        case .invalidMnemonic(let reason):
            return .invalidMnemonic(reason: reason)
        case .userCancelled:
            return .userCancelled
        }
    }
}
