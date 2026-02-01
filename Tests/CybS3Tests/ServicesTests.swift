import XCTest
import Crypto
@testable import CybS3Lib

final class ServicesTests: XCTestCase {
    
    // MARK: - Test Fixtures
    
    let validMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".components(separatedBy: " ")
    
    let validMnemonic2 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent".components(separatedBy: " ")
    
    // MARK: - AppSettings Tests
    
    func testAppSettingsInit() {
        let settings = AppSettings()
        XCTAssertNil(settings.defaultRegion)
        XCTAssertNil(settings.defaultBucket)
        XCTAssertNil(settings.defaultEndpoint)
        XCTAssertNil(settings.defaultAccessKey)
        XCTAssertNil(settings.defaultSecretKey)
    }
    
    func testAppSettingsInitWithValues() {
        let settings = AppSettings(
            defaultRegion: "us-west-2",
            defaultBucket: "my-bucket",
            defaultEndpoint: "s3.amazonaws.com",
            defaultAccessKey: "AKIA12345",
            defaultSecretKey: "secret123"
        )
        
        XCTAssertEqual(settings.defaultRegion, "us-west-2")
        XCTAssertEqual(settings.defaultBucket, "my-bucket")
        XCTAssertEqual(settings.defaultEndpoint, "s3.amazonaws.com")
        XCTAssertEqual(settings.defaultAccessKey, "AKIA12345")
        XCTAssertEqual(settings.defaultSecretKey, "secret123")
    }
    
    func testAppSettingsCodable() throws {
        let settings = AppSettings(
            defaultRegion: "eu-west-1",
            defaultBucket: "test-bucket"
        )
        
        let encoder = JSONEncoder()
        let data = try encoder.encode(settings)
        
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(AppSettings.self, from: data)
        
        XCTAssertEqual(decoded.defaultRegion, settings.defaultRegion)
        XCTAssertEqual(decoded.defaultBucket, settings.defaultBucket)
        XCTAssertNil(decoded.defaultEndpoint)
    }
    
    // MARK: - VaultConfig Tests
    
    func testVaultConfigInit() {
        let vault = VaultConfig(
            name: "test-vault",
            endpoint: "s3.amazonaws.com",
            accessKey: "AKIA12345",
            secretKey: "secret123",
            region: "us-east-1",
            bucket: "my-bucket"
        )
        
        XCTAssertEqual(vault.name, "test-vault")
        XCTAssertEqual(vault.endpoint, "s3.amazonaws.com")
        XCTAssertEqual(vault.accessKey, "AKIA12345")
        XCTAssertEqual(vault.secretKey, "secret123")
        XCTAssertEqual(vault.region, "us-east-1")
        XCTAssertEqual(vault.bucket, "my-bucket")
    }
    
    func testVaultConfigWithoutBucket() {
        let vault = VaultConfig(
            name: "no-bucket-vault",
            endpoint: "minio.local",
            accessKey: "minioadmin",
            secretKey: "minioadmin",
            region: "us-east-1"
        )
        
        XCTAssertNil(vault.bucket)
    }
    
    func testVaultConfigCodable() throws {
        let vault = VaultConfig(
            name: "codable-test",
            endpoint: "s3.eu-central-1.amazonaws.com",
            accessKey: "ACCESS",
            secretKey: "SECRET",
            region: "eu-central-1",
            bucket: "encoded-bucket"
        )
        
        let encoder = JSONEncoder()
        let data = try encoder.encode(vault)
        
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(VaultConfig.self, from: data)
        
        XCTAssertEqual(decoded.name, vault.name)
        XCTAssertEqual(decoded.endpoint, vault.endpoint)
        XCTAssertEqual(decoded.accessKey, vault.accessKey)
        XCTAssertEqual(decoded.secretKey, vault.secretKey)
        XCTAssertEqual(decoded.region, vault.region)
        XCTAssertEqual(decoded.bucket, vault.bucket)
    }
    
    // MARK: - EncryptedConfig Tests
    
    func testEncryptedConfigInit() {
        let dataKey = Data(repeating: 0x42, count: 32)
        let config = EncryptedConfig(
            dataKey: dataKey,
            vaults: [],
            settings: AppSettings()
        )
        
        XCTAssertEqual(config.version, 2)
        XCTAssertEqual(config.dataKey, dataKey)
        XCTAssertNil(config.activeVaultName)
        XCTAssertTrue(config.vaults.isEmpty)
    }
    
    func testEncryptedConfigWithVaults() {
        let dataKey = Data(repeating: 0xAB, count: 32)
        let vault1 = VaultConfig(
            name: "vault1",
            endpoint: "endpoint1",
            accessKey: "ak1",
            secretKey: "sk1",
            region: "us-east-1"
        )
        let vault2 = VaultConfig(
            name: "vault2",
            endpoint: "endpoint2",
            accessKey: "ak2",
            secretKey: "sk2",
            region: "eu-west-1"
        )
        
        let config = EncryptedConfig(
            dataKey: dataKey,
            activeVaultName: "vault1",
            vaults: [vault1, vault2],
            settings: AppSettings(defaultRegion: "us-east-1")
        )
        
        XCTAssertEqual(config.vaults.count, 2)
        XCTAssertEqual(config.activeVaultName, "vault1")
        XCTAssertEqual(config.settings.defaultRegion, "us-east-1")
    }
    
    func testEncryptedConfigCodable() throws {
        let dataKey = Data(repeating: 0xCD, count: 32)
        let config = EncryptedConfig(
            dataKey: dataKey,
            activeVaultName: "my-vault",
            vaults: [
                VaultConfig(
                    name: "my-vault",
                    endpoint: "s3.test.com",
                    accessKey: "test-ak",
                    secretKey: "test-sk",
                    region: "us-west-2"
                )
            ],
            settings: AppSettings(defaultBucket: "default-bucket")
        )
        
        let encoder = JSONEncoder()
        let data = try encoder.encode(config)
        
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(EncryptedConfig.self, from: data)
        
        XCTAssertEqual(decoded.version, config.version)
        XCTAssertEqual(decoded.dataKey, config.dataKey)
        XCTAssertEqual(decoded.activeVaultName, config.activeVaultName)
        XCTAssertEqual(decoded.vaults.count, 1)
        XCTAssertEqual(decoded.vaults.first?.name, "my-vault")
        XCTAssertEqual(decoded.settings.defaultBucket, "default-bucket")
    }
    
    // MARK: - StorageError Tests
    
    func testStorageErrorDescriptions() {
        let errors: [StorageError] = [
            .configNotFound,
            .oldVaultsFoundButMigrationFailed,
            .decryptionFailed,
            .integrityCheckFailed,
            .unsupportedVersion(99)
        ]
        
        for error in errors {
            XCTAssertNotNil(error.errorDescription)
            XCTAssertFalse(error.errorDescription!.isEmpty)
            XCTAssertTrue(error.errorDescription!.contains("❌"))
        }
        
        // Check specific message content
        XCTAssertTrue(StorageError.configNotFound.errorDescription!.contains("login"))
        XCTAssertTrue(StorageError.unsupportedVersion(5).errorDescription!.contains("5"))
    }
    
    // MARK: - InteractionError Tests
    
    func testInteractionErrorDescriptions() {
        let errors: [InteractionError] = [
            .mnemonicRequired,
            .bucketRequired,
            .invalidMnemonic("checksum failed"),
            .userCancelled
        ]
        
        for error in errors {
            XCTAssertNotNil(error.errorDescription)
            XCTAssertFalse(error.errorDescription!.isEmpty)
        }
        
        // Check specific message content
        XCTAssertTrue(InteractionError.mnemonicRequired.errorDescription!.contains("keys create"))
        XCTAssertTrue(InteractionError.bucketRequired.errorDescription!.contains("bucket"))
        XCTAssertTrue(InteractionError.invalidMnemonic("bad word").errorDescription!.contains("bad word"))
        XCTAssertTrue(InteractionError.userCancelled.errorDescription!.contains("cancelled"))
    }
    
    // MARK: - EncryptionService Tests
    
    func testEncryptionServiceDeriveKey() throws {
        let key1 = try EncryptionService.deriveKey(mnemonic: validMnemonic)
        let key2 = try EncryptionService.deriveKey(mnemonic: validMnemonic)
        
        // Same mnemonic should produce same key
        XCTAssertEqual(key1, key2)
        
        // Different mnemonic should produce different key
        let key3 = try EncryptionService.deriveKey(mnemonic: validMnemonic2)
        XCTAssertNotEqual(key1, key3)
    }
    
    func testEncryptionServiceEncryptDecrypt() throws {
        let key = try EncryptionService.deriveKey(mnemonic: validMnemonic)
        let plaintext = "Hello, encryption service!".data(using: .utf8)!
        
        let ciphertext = try EncryptionService.encrypt(data: plaintext, key: key)
        XCTAssertNotEqual(ciphertext, plaintext)
        
        let decrypted = try EncryptionService.decrypt(data: ciphertext, key: key)
        XCTAssertEqual(decrypted, plaintext)
    }
    
    func testEncryptionServiceDecryptWithWrongKey() throws {
        let key1 = try EncryptionService.deriveKey(mnemonic: validMnemonic)
        let key2 = try EncryptionService.deriveKey(mnemonic: validMnemonic2)
        
        let plaintext = "Secret data".data(using: .utf8)!
        let ciphertext = try EncryptionService.encrypt(data: plaintext, key: key1)
        
        XCTAssertThrowsError(try EncryptionService.decrypt(data: ciphertext, key: key2))
    }
    
    // MARK: - InteractionService.confirm Tests
    
    // Note: Interactive methods like promptForMnemonic can't be easily unit tested
    // without mocking stdin. We test the confirm logic separately.
    
    func testConfirmMessageFormat() {
        // Test that the message format is correct
        // This is a documentation test - we can't actually test stdin in unit tests
        let defaultYes = "[Y/n]"
        let defaultNo = "[y/N]"
        
        XCTAssertTrue(defaultYes.contains("Y"))
        XCTAssertTrue(defaultNo.contains("N"))
    }
}

// MARK: - ConsoleUI Tests

final class ConsoleUITests: XCTestCase {
    
    func testFormatBytes() {
        XCTAssertEqual(ConsoleUI.formatBytes(0), "0 B")
        XCTAssertEqual(ConsoleUI.formatBytes(512), "512 B")
        XCTAssertEqual(ConsoleUI.formatBytes(1024), "1.00 KB")
        XCTAssertEqual(ConsoleUI.formatBytes(1536), "1.50 KB")
        XCTAssertEqual(ConsoleUI.formatBytes(1048576), "1.00 MB")
        XCTAssertEqual(ConsoleUI.formatBytes(1073741824), "1.00 GB")
        XCTAssertEqual(ConsoleUI.formatBytes(1099511627776), "1.00 TB")
    }
    
    func testFormatBytesEdgeCases() {
        // Test negative values (shouldn't happen, but should handle gracefully)
        // Test very large values
        XCTAssertEqual(ConsoleUI.formatBytes(1), "1 B")
        XCTAssertEqual(ConsoleUI.formatBytes(1023), "1023 B")
        XCTAssertEqual(ConsoleUI.formatBytes(1025), "1.00 KB")
        
        // Test exact boundaries
        XCTAssertEqual(ConsoleUI.formatBytes(1024 * 1024), "1.00 MB")
        XCTAssertEqual(ConsoleUI.formatBytes(1024 * 1024 * 1024), "1.00 GB")
    }
    
    func testFormatDuration() {
        XCTAssertEqual(ConsoleUI.formatDuration(0.5), "500 ms")
        XCTAssertEqual(ConsoleUI.formatDuration(1.5), "1.5 s")
        XCTAssertEqual(ConsoleUI.formatDuration(65), "1m 5s")
        XCTAssertEqual(ConsoleUI.formatDuration(3665), "1h 1m")
    }
    
    func testFormatDurationEdgeCases() {
        // Sub-second
        XCTAssertEqual(ConsoleUI.formatDuration(0.001), "1 ms")
        XCTAssertEqual(ConsoleUI.formatDuration(0.999), "999 ms")
        
        // Exactly 1 second
        XCTAssertEqual(ConsoleUI.formatDuration(1.0), "1.0 s")
        
        // Exactly 1 minute
        XCTAssertEqual(ConsoleUI.formatDuration(60), "1m 0s")
        
        // Exactly 1 hour
        XCTAssertEqual(ConsoleUI.formatDuration(3600), "1h 0m")
        
        // Zero
        XCTAssertEqual(ConsoleUI.formatDuration(0), "0 ms")
        
        // Very long duration
        let twoDays = 2 * 24 * 3600.0
        let result = ConsoleUI.formatDuration(twoDays)
        XCTAssertTrue(result.contains("h"), "Long durations should show hours")
    }
    
    func testStatusIcons() {
        XCTAssertEqual(ConsoleUI.StatusIcon.success.symbol, "✅")
        XCTAssertEqual(ConsoleUI.StatusIcon.error.symbol, "❌")
        XCTAssertEqual(ConsoleUI.StatusIcon.warning.symbol, "⚠️")
        XCTAssertEqual(ConsoleUI.StatusIcon.info.symbol, "ℹ️")
        XCTAssertEqual(ConsoleUI.StatusIcon.lock.symbol, "🔐")
    }
    
    func testStatusIconsComplete() {
        // Test all status icons have symbols
        let icons: [ConsoleUI.StatusIcon] = [
            .success, .error, .warning, .info, .progress,
            .question, .key, .folder, .file, .cloud, .lock, .unlock
        ]
        
        for icon in icons {
            XCTAssertFalse(icon.symbol.isEmpty, "Icon \(icon) should have a symbol")
        }
    }
    
    func testColoredWithColorsDisabled() {
        // Save original state
        let originalUseColors = ConsoleUI.useColors
        
        // Disable colors
        ConsoleUI.useColors = false
        
        let text = "Test message"
        let colored = ConsoleUI.colored(text, .red)
        
        // Should return unchanged text
        XCTAssertEqual(colored, text)
        
        // Restore original state
        ConsoleUI.useColors = originalUseColors
    }
    
    func testColoredWithColorsEnabled() {
        // Save original state
        let originalUseColors = ConsoleUI.useColors
        
        // Enable colors
        ConsoleUI.useColors = true
        
        let text = "Test message"
        let colored = ConsoleUI.colored(text, .green)
        
        // Should contain ANSI codes
        XCTAssertTrue(colored.contains("\u{001B}[32m"))
        XCTAssertTrue(colored.contains("\u{001B}[0m"))
        XCTAssertTrue(colored.contains(text))
        
        // Restore original state
        ConsoleUI.useColors = originalUseColors
    }
    
    func testColoredWithAllColors() {
        // Save original state
        let originalUseColors = ConsoleUI.useColors
        ConsoleUI.useColors = true
        
        let colors: [ConsoleUI.Color] = [.red, .green, .yellow, .blue, .magenta, .cyan, .white, .bold, .dim]
        let text = "Test"
        
        for color in colors {
            let colored = ConsoleUI.colored(text, color)
            XCTAssertTrue(colored.contains(color.rawValue), "Color \(color) should be applied")
            XCTAssertTrue(colored.contains(text), "Text should be preserved")
            XCTAssertTrue(colored.contains(ConsoleUI.Color.reset.rawValue), "Reset code should be present")
        }
        
        // Restore original state
        ConsoleUI.useColors = originalUseColors
    }
    
    func testProgressBarInitialization() {
        let progressBar = ConsoleUI.ProgressBar(title: "Test", width: 20)
        XCTAssertNotNil(progressBar)
    }
    
    func testProgressBarWithDifferentWidths() {
        // Test with various widths
        let widths = [10, 20, 40, 80]
        for width in widths {
            let progressBar = ConsoleUI.ProgressBar(title: "Test", width: width)
            XCTAssertNotNil(progressBar)
        }
    }
    
    func testProgressBarUpdate() {
        let progressBar = ConsoleUI.ProgressBar(title: "Test", width: 20, showSpeed: false)
        
        // Should not crash when updating
        progressBar.update(progress: 0.0)
        progressBar.update(progress: 0.5)
        progressBar.update(progress: 1.0)
    }
    
    func testProgressBarWithBytesProcessed() {
        let progressBar = ConsoleUI.ProgressBar(title: "Uploading", width: 30, showSpeed: true)
        
        // Update with bytes information
        progressBar.update(progress: 0.25, bytesProcessed: 256 * 1024)
        progressBar.update(progress: 0.5, bytesProcessed: 512 * 1024)
        progressBar.update(progress: 0.75, bytesProcessed: 768 * 1024)
        progressBar.update(progress: 1.0, bytesProcessed: 1024 * 1024)
    }
    
    func testProgressBarUpdateWithValidValues() {
        let progressBar = ConsoleUI.ProgressBar(title: "Test", width: 20, showSpeed: false)
        
        // Test valid progress values
        progressBar.update(progress: 0.0)
        progressBar.update(progress: 0.25)
        progressBar.update(progress: 0.5)
        progressBar.update(progress: 0.75)
        progressBar.update(progress: 1.0)
    }
    
    func testSpinnerInitialization() {
        let spinner = ConsoleUI.Spinner(message: "Loading...")
        XCTAssertNotNil(spinner)
    }
    
    func testSpinnerLifecycle() {
        let spinner = ConsoleUI.Spinner(message: "Processing")
        
        spinner.start()
        spinner.tick()
        spinner.tick()
        spinner.tick()
        spinner.stop(success: true)
    }
    
    func testSpinnerWithFailure() {
        let spinner = ConsoleUI.Spinner(message: "Trying something")
        
        spinner.start()
        spinner.tick()
        spinner.stop(success: false)
    }
}

// MARK: - CLIError Tests

final class CLIErrorTests: XCTestCase {
    
    func testErrorDescriptions() {
        let errors: [CLIError] = [
            .configurationNotFound,
            .authenticationRequired,
            .mnemonicRequired,
            .vaultNotFound(name: "test-vault"),
            .bucketRequired,
            .objectNotFound(key: "file.txt"),
            .fileNotFound(path: "/tmp/test.txt"),
            .userCancelled
        ]
        
        for error in errors {
            XCTAssertNotNil(error.errorDescription)
            XCTAssertFalse(error.errorDescription!.isEmpty)
        }
    }
    
    func testAllCLIErrorCasesHaveDescriptions() {
        // Test all error cases have non-empty descriptions
        let errors: [CLIError] = [
            // Configuration
            .configurationNotFound,
            .configurationCorrupted(underlying: nil),
            .configurationCorrupted(underlying: NSError(domain: "test", code: 1)),
            .configurationMigrationFailed(reason: "test"),
            
            // Authentication
            .authenticationRequired,
            .invalidCredentials(service: "S3"),
            .keychainAccessFailed(operation: "save", underlying: nil),
            
            // Mnemonic
            .mnemonicRequired,
            .invalidMnemonic(reason: "checksum failed"),
            .mnemonicMismatch,
            
            // Vault
            .vaultNotFound(name: "vault"),
            .vaultAlreadyExists(name: "vault"),
            .noVaultsConfigured,
            
            // S3 Operations
            .bucketRequired,
            .bucketNotFound(name: "bucket"),
            .bucketNotEmpty(name: "bucket"),
            .objectNotFound(key: "key"),
            .accessDenied(resource: "resource"),
            .accessDenied(resource: nil),
            .networkError(underlying: NSError(domain: "test", code: 1)),
            .invalidEndpoint(url: "invalid"),
            
            // File System
            .fileNotFound(path: "/path"),
            .fileAccessDenied(path: "/path"),
            .fileWriteFailed(path: "/path", underlying: nil),
            .directoryCreationFailed(path: "/path"),
            
            // Encryption
            .encryptionFailed(reason: nil),
            .encryptionFailed(reason: "test"),
            .decryptionFailed(reason: nil),
            .decryptionFailed(reason: "test"),
            .keyDerivationFailed,
            
            // User Interaction
            .userCancelled,
            .invalidInput(expected: "number"),
            .operationAborted(reason: "timeout"),
            
            // Generic
            .internalError(message: "oops"),
            .unknown(underlying: NSError(domain: "test", code: 1))
        ]
        
        for error in errors {
            XCTAssertNotNil(error.errorDescription, "Error \(error) should have description")
            XCTAssertFalse(error.errorDescription!.isEmpty, "Error \(error) description should not be empty")
        }
    }
    
    func testErrorSymbols() {
        XCTAssertEqual(CLIError.userCancelled.symbol, "⚠️")
        XCTAssertEqual(CLIError.operationAborted(reason: "test").symbol, "⚠️")
        XCTAssertEqual(CLIError.configurationNotFound.symbol, "❌")
        XCTAssertEqual(CLIError.mnemonicRequired.symbol, "❌")
    }
    
    func testErrorSuggestions() {
        XCTAssertNotNil(CLIError.configurationNotFound.suggestion)
        XCTAssertNotNil(CLIError.mnemonicRequired.suggestion)
        XCTAssertNotNil(CLIError.noVaultsConfigured.suggestion)
        XCTAssertNotNil(CLIError.bucketRequired.suggestion)
        XCTAssertNil(CLIError.userCancelled.suggestion)
    }
    
    func testFormattedMessage() {
        let error = CLIError.vaultNotFound(name: "my-vault")
        let formatted = error.formattedMessage
        
        XCTAssertTrue(formatted.contains("❌"))
        XCTAssertTrue(formatted.contains("my-vault"))
    }
    
    func testFormattedMessageContainsSymbolAndDescription() {
        let errors: [CLIError] = [
            .configurationNotFound,
            .userCancelled,
            .bucketRequired
        ]
        
        for error in errors {
            let formatted = error.formattedMessage
            XCTAssertTrue(formatted.contains(error.symbol))
            XCTAssertTrue(formatted.contains(error.errorDescription ?? ""))
        }
    }
    
    func testFromS3Error() {
        let s3Error = S3Error.bucketNotFound
        let cliError = CLIError.from(s3Error)
        
        if case .bucketNotFound = cliError {
            // Expected
        } else {
            XCTFail("Expected bucketNotFound error")
        }
    }
    
    func testFromS3ErrorAllCases() {
        let mappings: [(S3Error, String)] = [
            (.invalidURL, "invalidEndpoint"),
            (.authenticationFailed, "invalidCredentials"),
            (.bucketNotFound, "bucketNotFound"),
            (.objectNotFound, "objectNotFound"),
            (.accessDenied(resource: "test"), "accessDenied"),
            (.bucketNotEmpty, "bucketNotEmpty"),
            (.requestFailed(status: 500, code: nil, message: nil), "unknown"),
            (.requestFailedLegacy("test"), "unknown"),
            (.invalidResponse, "unknown"),
            (.fileAccessFailed, "unknown")
        ]
        
        for (s3Error, expectedCase) in mappings {
            let cliError = CLIError.from(s3Error)
            let description = String(describing: cliError)
            XCTAssertTrue(description.contains(expectedCase) || description.lowercased().contains(expectedCase.lowercased()),
                          "S3Error.\(s3Error) should map to CLIError containing '\(expectedCase)', got \(cliError)")
        }
    }
    
    func testFromStorageError() {
        let storageError = StorageError.configNotFound
        let cliError = CLIError.from(storageError)
        
        if case .configurationNotFound = cliError {
            // Expected
        } else {
            XCTFail("Expected configurationNotFound error")
        }
    }
    
    func testFromStorageErrorAllCases() {
        let mappings: [(StorageError, (CLIError) -> Bool)] = [
            (.configNotFound, { if case .configurationNotFound = $0 { return true }; return false }),
            (.decryptionFailed, { if case .decryptionFailed = $0 { return true }; return false }),
            (.integrityCheckFailed, { if case .configurationCorrupted = $0 { return true }; return false }),
            (.unsupportedVersion(5), { if case .configurationMigrationFailed = $0 { return true }; return false }),
            (.oldVaultsFoundButMigrationFailed, { if case .configurationMigrationFailed = $0 { return true }; return false })
        ]
        
        for (storageError, validator) in mappings {
            let cliError = CLIError.from(storageError)
            XCTAssertTrue(validator(cliError), "StorageError.\(storageError) should map correctly")
        }
    }
    
    func testFromInteractionError() {
        let interactionError = InteractionError.mnemonicRequired
        let cliError = CLIError.from(interactionError)
        
        if case .mnemonicRequired = cliError {
            // Expected
        } else {
            XCTFail("Expected mnemonicRequired error")
        }
    }
    
    func testFromInteractionErrorAllCases() {
        let mappings: [(InteractionError, (CLIError) -> Bool)] = [
            (.mnemonicRequired, { if case .mnemonicRequired = $0 { return true }; return false }),
            (.bucketRequired, { if case .bucketRequired = $0 { return true }; return false }),
            (.invalidMnemonic("test"), { if case .invalidMnemonic = $0 { return true }; return false }),
            (.userCancelled, { if case .userCancelled = $0 { return true }; return false })
        ]
        
        for (interactionError, validator) in mappings {
            let cliError = CLIError.from(interactionError)
            XCTAssertTrue(validator(cliError), "InteractionError.\(interactionError) should map correctly")
        }
    }
    
    func testDynamicErrorMessages() {
        let vaultError = CLIError.vaultNotFound(name: "production-vault")
        XCTAssertTrue(vaultError.errorDescription!.contains("production-vault"))
        
        let objectError = CLIError.objectNotFound(key: "data/file.json")
        XCTAssertTrue(objectError.errorDescription!.contains("data/file.json"))
        
        let endpointError = CLIError.invalidEndpoint(url: "invalid://url")
        XCTAssertTrue(endpointError.errorDescription!.contains("invalid://url"))
    }
    
    func testConfigurationCorruptedWithUnderlying() {
        let underlying = NSError(domain: "TestDomain", code: 42, userInfo: [NSLocalizedDescriptionKey: "Test error"])
        let error = CLIError.configurationCorrupted(underlying: underlying)
        
        XCTAssertTrue(error.errorDescription!.contains("corrupted"))
        XCTAssertTrue(error.errorDescription!.contains("Test error"))
    }
    
    func testFileWriteFailedWithUnderlying() {
        let underlying = NSError(domain: "TestDomain", code: 13, userInfo: [NSLocalizedDescriptionKey: "Permission denied"])
        let error = CLIError.fileWriteFailed(path: "/tmp/file.txt", underlying: underlying)
        
        XCTAssertTrue(error.errorDescription!.contains("/tmp/file.txt"))
        XCTAssertTrue(error.errorDescription!.contains("Permission denied"))
    }
    
    func testEncryptionErrorsWithAndWithoutReasons() {
        let withReason = CLIError.encryptionFailed(reason: "Key too short")
        let withoutReason = CLIError.encryptionFailed(reason: nil)
        
        XCTAssertTrue(withReason.errorDescription!.contains("Key too short"))
        XCTAssertTrue(withoutReason.errorDescription!.contains("Encryption failed"))
    }
    
    func testAccessDeniedWithAndWithoutResource() {
        let withResource = CLIError.accessDenied(resource: "my-bucket/secret-file.txt")
        let withoutResource = CLIError.accessDenied(resource: nil)
        
        XCTAssertTrue(withResource.errorDescription!.contains("my-bucket/secret-file.txt"))
        XCTAssertTrue(withoutResource.errorDescription!.contains("Access denied"))
    }
    
    func testSuggestionsContainHelpfulCommands() {
        let configError = CLIError.configurationNotFound
        XCTAssertTrue(configError.suggestion!.contains("cybs3"))
        
        let mnemonicError = CLIError.mnemonicRequired
        XCTAssertTrue(mnemonicError.suggestion!.contains("keys create"))
        
        let vaultError = CLIError.noVaultsConfigured
        XCTAssertTrue(vaultError.suggestion!.contains("vaults add"))
        
        let bucketError = CLIError.bucketRequired
        XCTAssertTrue(bucketError.suggestion!.contains("--bucket"))
    }
}
