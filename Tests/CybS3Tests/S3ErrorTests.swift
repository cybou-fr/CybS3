import XCTest
@testable import CybS3Lib

final class S3ErrorTests: XCTestCase {
    
    // MARK: - S3Error Description Tests
    
    func testAllS3ErrorsHaveDescriptions() {
        let errors: [S3Error] = [
            .invalidURL,
            .authenticationFailed,
            .requestFailed(status: 500, code: "InternalError", message: "Server error"),
            .requestFailed(status: 400, code: nil, message: nil),
            .requestFailedLegacy("Legacy error message"),
            .invalidResponse,
            .bucketNotFound,
            .objectNotFound,
            .fileAccessFailed,
            .accessDenied(resource: "bucket/key"),
            .accessDenied(resource: nil),
            .bucketNotEmpty
        ]
        
        for error in errors {
            XCTAssertNotNil(error.errorDescription, "Error \(error) should have a description")
            XCTAssertFalse(error.errorDescription!.isEmpty, "Error \(error) description should not be empty")
            XCTAssertTrue(error.errorDescription!.contains("❌"), "Error \(error) should include error symbol")
        }
    }
    
    func testInvalidURLError() {
        let error = S3Error.invalidURL
        XCTAssertTrue(error.errorDescription!.contains("Invalid URL"))
        XCTAssertTrue(error.errorDescription!.contains("endpoint"))
    }
    
    func testAuthenticationFailedError() {
        let error = S3Error.authenticationFailed
        XCTAssertTrue(error.errorDescription!.contains("Authentication Failed"))
        XCTAssertTrue(error.errorDescription!.contains("Access Key"))
        XCTAssertTrue(error.errorDescription!.contains("Secret Key"))
    }
    
    func testRequestFailedWithAllDetails() {
        let error = S3Error.requestFailed(status: 403, code: "AccessDenied", message: "Access Denied")
        let description = error.errorDescription!
        
        XCTAssertTrue(description.contains("403"))
        XCTAssertTrue(description.contains("AccessDenied"))
        XCTAssertTrue(description.contains("Access Denied"))
    }
    
    func testRequestFailedWithPartialDetails() {
        let errorNoCode = S3Error.requestFailed(status: 500, code: nil, message: "Server error")
        XCTAssertTrue(errorNoCode.errorDescription!.contains("500"))
        XCTAssertTrue(errorNoCode.errorDescription!.contains("Server error"))
        XCTAssertFalse(errorNoCode.errorDescription!.contains("Code:"))
        
        let errorNoMessage = S3Error.requestFailed(status: 404, code: "NotFound", message: nil)
        XCTAssertTrue(errorNoMessage.errorDescription!.contains("404"))
        XCTAssertTrue(errorNoMessage.errorDescription!.contains("NotFound"))
    }
    
    func testBucketNotFoundError() {
        let error = S3Error.bucketNotFound
        XCTAssertTrue(error.errorDescription!.contains("Bucket"))
        XCTAssertTrue(error.errorDescription!.contains("--bucket"))
    }
    
    func testObjectNotFoundError() {
        let error = S3Error.objectNotFound
        XCTAssertTrue(error.errorDescription!.contains("Object"))
        XCTAssertTrue(error.errorDescription!.contains("key"))
    }
    
    func testAccessDeniedWithResource() {
        let error = S3Error.accessDenied(resource: "my-bucket/secret-file.txt")
        XCTAssertTrue(error.errorDescription!.contains("my-bucket/secret-file.txt"))
        XCTAssertTrue(error.errorDescription!.contains("permission"))
    }
    
    func testAccessDeniedWithoutResource() {
        let error = S3Error.accessDenied(resource: nil)
        XCTAssertTrue(error.errorDescription!.contains("Access Denied"))
        XCTAssertTrue(error.errorDescription!.contains("credentials"))
    }
    
    func testBucketNotEmptyError() {
        let error = S3Error.bucketNotEmpty
        XCTAssertTrue(error.errorDescription!.contains("Bucket Not Empty"))
        XCTAssertTrue(error.errorDescription!.contains("Delete all objects"))
    }
    
    // MARK: - S3ErrorParser Tests
    
    func testParseAccessDeniedError() {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <Error>
            <Code>AccessDenied</Code>
            <Message>Access Denied</Message>
            <RequestId>12345</RequestId>
            <HostId>abcdef</HostId>
        </Error>
        """
        
        let error = S3ErrorParser.parse(data: xml.data(using: .utf8)!, status: 403)
        
        if case .accessDenied = error {
            // Expected
        } else {
            XCTFail("Expected accessDenied error, got \(error)")
        }
    }
    
    func testParseNoSuchBucketError() {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <Error>
            <Code>NoSuchBucket</Code>
            <Message>The specified bucket does not exist</Message>
        </Error>
        """
        
        let error = S3ErrorParser.parse(data: xml.data(using: .utf8)!, status: 404)
        
        if case .bucketNotFound = error {
            // Expected
        } else {
            XCTFail("Expected bucketNotFound error, got \(error)")
        }
    }
    
    func testParseNoSuchKeyError() {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <Error>
            <Code>NoSuchKey</Code>
            <Message>The specified key does not exist.</Message>
        </Error>
        """
        
        let error = S3ErrorParser.parse(data: xml.data(using: .utf8)!, status: 404)
        
        if case .objectNotFound = error {
            // Expected
        } else {
            XCTFail("Expected objectNotFound error, got \(error)")
        }
    }
    
    func testParseBucketNotEmptyError() {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <Error>
            <Code>BucketNotEmpty</Code>
            <Message>The bucket you tried to delete is not empty</Message>
        </Error>
        """
        
        let error = S3ErrorParser.parse(data: xml.data(using: .utf8)!, status: 409)
        
        if case .bucketNotEmpty = error {
            // Expected
        } else {
            XCTFail("Expected bucketNotEmpty error, got \(error)")
        }
    }
    
    func testParseInvalidAccessKeyIdError() {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <Error>
            <Code>InvalidAccessKeyId</Code>
            <Message>The AWS Access Key Id you provided does not exist in our records.</Message>
        </Error>
        """
        
        let error = S3ErrorParser.parse(data: xml.data(using: .utf8)!, status: 403)
        
        if case .authenticationFailed = error {
            // Expected
        } else {
            XCTFail("Expected authenticationFailed error, got \(error)")
        }
    }
    
    func testParseSignatureDoesNotMatchError() {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <Error>
            <Code>SignatureDoesNotMatch</Code>
            <Message>The request signature we calculated does not match the signature you provided.</Message>
        </Error>
        """
        
        let error = S3ErrorParser.parse(data: xml.data(using: .utf8)!, status: 403)
        
        if case .authenticationFailed = error {
            // Expected
        } else {
            XCTFail("Expected authenticationFailed error, got \(error)")
        }
    }
    
    func testParseUnknownErrorCode() {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <Error>
            <Code>UnknownErrorCode</Code>
            <Message>Something went wrong</Message>
        </Error>
        """
        
        let error = S3ErrorParser.parse(data: xml.data(using: .utf8)!, status: 500)
        
        if case .requestFailed(let status, let code, let message) = error {
            XCTAssertEqual(status, 500)
            XCTAssertEqual(code, "UnknownErrorCode")
            XCTAssertEqual(message, "Something went wrong")
        } else {
            XCTFail("Expected requestFailed error, got \(error)")
        }
    }
    
    func testParseInvalidXML() {
        let invalidXML = "This is not valid XML at all!"
        
        let error = S3ErrorParser.parse(data: invalidXML.data(using: .utf8)!, status: 500)
        
        if case .requestFailed(let status, let code, let message) = error {
            XCTAssertEqual(status, 500)
            XCTAssertNil(code)
            XCTAssertNotNil(message) // Should contain raw message
        } else {
            XCTFail("Expected requestFailed error, got \(error)")
        }
    }
    
    func testParseEmptyErrorResponse() {
        let error = S3ErrorParser.parse(data: Data(), status: 500)
        
        if case .requestFailed(let status, _, _) = error {
            XCTAssertEqual(status, 500)
        } else {
            XCTFail("Expected requestFailed error, got \(error)")
        }
    }
    
    // MARK: - S3Endpoint Tests
    
    func testS3EndpointHTTPS() {
        let endpoint = S3Endpoint(host: "s3.amazonaws.com", port: 443, useSSL: true)
        
        XCTAssertEqual(endpoint.host, "s3.amazonaws.com")
        XCTAssertEqual(endpoint.port, 443)
        XCTAssertTrue(endpoint.useSSL)
        XCTAssertEqual(endpoint.scheme, "https")
        
        XCTAssertNotNil(endpoint.url)
        XCTAssertEqual(endpoint.url?.scheme, "https")
        XCTAssertEqual(endpoint.url?.host, "s3.amazonaws.com")
    }
    
    func testS3EndpointHTTP() {
        let endpoint = S3Endpoint(host: "minio.local", port: 9000, useSSL: false)
        
        XCTAssertEqual(endpoint.host, "minio.local")
        XCTAssertEqual(endpoint.port, 9000)
        XCTAssertFalse(endpoint.useSSL)
        XCTAssertEqual(endpoint.scheme, "http")
        
        XCTAssertNotNil(endpoint.url)
        XCTAssertEqual(endpoint.url?.scheme, "http")
        XCTAssertEqual(endpoint.url?.port, 9000)
    }
    
    func testS3EndpointURLConstruction() {
        let endpoint = S3Endpoint(host: "s3.eu-west-1.amazonaws.com", port: 443, useSSL: true)
        
        guard let url = endpoint.url else {
            XCTFail("URL should not be nil")
            return
        }
        
        XCTAssertEqual(url.absoluteString, "https://s3.eu-west-1.amazonaws.com:443")
    }
}

// MARK: - Streaming Encryption Error Tests

final class StreamingEncryptionErrorTests: XCTestCase {
    
    func testAllErrorsHaveDescriptions() {
        let errors: [StreamingEncryptionError] = [
            .encryptionFailed,
            .decryptionFailed,
            .invalidData
        ]
        
        for error in errors {
            XCTAssertNotNil(error.errorDescription)
            XCTAssertFalse(error.errorDescription!.isEmpty)
            XCTAssertTrue(error.errorDescription!.contains("❌"))
        }
    }
    
    func testEncryptionFailedError() {
        let error = StreamingEncryptionError.encryptionFailed
        XCTAssertTrue(error.errorDescription!.contains("Encryption failed"))
    }
    
    func testDecryptionFailedError() {
        let error = StreamingEncryptionError.decryptionFailed
        XCTAssertTrue(error.errorDescription!.contains("Decryption failed"))
        XCTAssertTrue(error.errorDescription!.contains("corrupted") || error.errorDescription!.contains("key"))
    }
    
    func testInvalidDataError() {
        let error = StreamingEncryptionError.invalidData
        XCTAssertTrue(error.errorDescription!.contains("Invalid"))
    }
}

// MARK: - Keychain Error Tests

final class KeychainErrorTests: XCTestCase {
    
    func testAllErrorsHaveDescriptions() {
        let errors: [KeychainError] = [
            .duplicateEntry,
            .unknown(-1),
            .itemNotFound,
            .accessControlCreationFailed,
            .biometricNotAvailable
        ]
        
        for error in errors {
            XCTAssertNotNil(error.errorDescription)
            XCTAssertFalse(error.errorDescription!.isEmpty)
            XCTAssertTrue(error.errorDescription!.contains("❌"))
        }
    }
    
    func testDuplicateEntryError() {
        let error = KeychainError.duplicateEntry
        XCTAssertTrue(error.errorDescription!.contains("already exists"))
    }
    
    func testItemNotFoundError() {
        let error = KeychainError.itemNotFound
        XCTAssertTrue(error.errorDescription!.contains("No mnemonic found"))
        XCTAssertTrue(error.errorDescription!.contains("login"))
    }
    
    func testUnknownErrorWithStatus() {
        let error = KeychainError.unknown(-25300)
        XCTAssertTrue(error.errorDescription!.contains("-25300"))
    }
    
    func testBiometricNotAvailableError() {
        let error = KeychainError.biometricNotAvailable
        XCTAssertTrue(error.errorDescription!.contains("Biometric"))
    }
}
