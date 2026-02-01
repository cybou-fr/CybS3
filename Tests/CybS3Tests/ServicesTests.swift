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
    
    func testFormatDuration() {
        XCTAssertEqual(ConsoleUI.formatDuration(0.5), "500 ms")
        XCTAssertEqual(ConsoleUI.formatDuration(1.5), "1.5 s")
        XCTAssertEqual(ConsoleUI.formatDuration(65), "1m 5s")
        XCTAssertEqual(ConsoleUI.formatDuration(3665), "1h 1m")
    }
    
    func testStatusIcons() {
        XCTAssertEqual(ConsoleUI.StatusIcon.success.symbol, "✅")
        XCTAssertEqual(ConsoleUI.StatusIcon.error.symbol, "❌")
        XCTAssertEqual(ConsoleUI.StatusIcon.warning.symbol, "⚠️")
        XCTAssertEqual(ConsoleUI.StatusIcon.info.symbol, "ℹ️")
        XCTAssertEqual(ConsoleUI.StatusIcon.lock.symbol, "🔐")
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
    
    func testProgressBarInitialization() {
        let progressBar = ConsoleUI.ProgressBar(title: "Test", width: 20)
        XCTAssertNotNil(progressBar)
    }
    
    func testSpinnerInitialization() {
        let spinner = ConsoleUI.Spinner(message: "Loading...")
        XCTAssertNotNil(spinner)
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
    
    func testFromS3Error() {
        let s3Error = S3Error.bucketNotFound
        let cliError = CLIError.from(s3Error)
        
        if case .bucketNotFound = cliError {
            // Expected
        } else {
            XCTFail("Expected bucketNotFound error")
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
    
    func testFromInteractionError() {
        let interactionError = InteractionError.mnemonicRequired
        let cliError = CLIError.from(interactionError)
        
        if case .mnemonicRequired = cliError {
            // Expected
        } else {
            XCTFail("Expected mnemonicRequired error")
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
}
