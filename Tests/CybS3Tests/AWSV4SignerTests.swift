import XCTest
import AsyncHTTPClient
import NIOHTTP1
@testable import CybS3Lib

final class AWSV4SignerTests: XCTestCase {
    
    // MARK: - Test Fixtures
    
    let testAccessKey = "AKIAIOSFODNN7EXAMPLE"
    let testSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    let testRegion = "us-east-1"
    
    // Fixed timestamp for deterministic tests
    var fixedTimestamp: Date {
        Date(timeIntervalSince1970: 1369353600) // 2013-05-24T00:00:00Z
    }
    
    // MARK: - Basic Signing Tests
    
    func testSignRequest() throws {
        let signer = AWSV4Signer(accessKey: testAccessKey, secretKey: testSecretKey, region: testRegion)
        
        let url = URL(string: "https://examplebucket.s3.amazonaws.com/test.txt")!
        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = .GET
        
        signer.sign(
            request: &request,
            url: url,
            method: "GET",
            bodyHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // Empty hash
            headers: [:],
            now: fixedTimestamp
        )
        
        // Check Headers
        XCTAssertNotNil(request.headers.first(name: "Authorization"))
        XCTAssertNotNil(request.headers.first(name: "x-amz-date"))
        XCTAssertNotNil(request.headers.first(name: "x-amz-content-sha256"))
        
        let authHeader = request.headers.first(name: "Authorization")!
        
        XCTAssertTrue(authHeader.hasPrefix("AWS4-HMAC-SHA256"))
        XCTAssertTrue(authHeader.contains("Credential=\(testAccessKey)/20130524/\(testRegion)/s3/aws4_request"))
        XCTAssertTrue(authHeader.contains("Signature="))
        
        let dateHeader = request.headers.first(name: "x-amz-date")!
        XCTAssertEqual(dateHeader, "20130524T000000Z")
    }
    
    func testSignRequestWithDifferentMethods() throws {
        let signer = AWSV4Signer(accessKey: testAccessKey, secretKey: testSecretKey, region: testRegion)
        let url = URL(string: "https://bucket.s3.amazonaws.com/object")!
        
        let methods = ["GET", "PUT", "POST", "DELETE", "HEAD"]
        
        for method in methods {
            var request = HTTPClientRequest(url: url.absoluteString)
            request.method = HTTPMethod(rawValue: method)
            
            signer.sign(
                request: &request,
                url: url,
                method: method,
                bodyHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                headers: [:],
                now: fixedTimestamp
            )
            
            XCTAssertNotNil(request.headers.first(name: "Authorization"), "Auth header missing for \(method)")
        }
    }
    
    func testSignRequestWithCustomHeaders() throws {
        let signer = AWSV4Signer(accessKey: testAccessKey, secretKey: testSecretKey, region: testRegion)
        let url = URL(string: "https://bucket.s3.amazonaws.com/object")!
        
        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = .PUT
        
        let customHeaders = [
            "Content-Type": "application/json",
            "x-amz-meta-custom": "custom-value"
        ]
        
        signer.sign(
            request: &request,
            url: url,
            method: "PUT",
            bodyHash: "abc123",
            headers: customHeaders,
            now: fixedTimestamp
        )
        
        // Custom headers should be present
        XCTAssertNotNil(request.headers.first(name: "Content-Type"))
        XCTAssertNotNil(request.headers.first(name: "x-amz-meta-custom"))
        
        // Custom headers should be included in signed headers
        let authHeader = request.headers.first(name: "Authorization")!
        XCTAssertTrue(authHeader.contains("content-type"))
        XCTAssertTrue(authHeader.contains("x-amz-meta-custom"))
    }
    
    func testSignRequestWithBodyHash() throws {
        let signer = AWSV4Signer(accessKey: testAccessKey, secretKey: testSecretKey, region: testRegion)
        let url = URL(string: "https://bucket.s3.amazonaws.com/object")!
        
        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = .PUT
        
        let bodyHash = "5d41402abc4b2a76b9719d911017c592" // Hash of "hello"
        
        signer.sign(
            request: &request,
            url: url,
            method: "PUT",
            bodyHash: bodyHash,
            headers: [:],
            now: fixedTimestamp
        )
        
        let contentSha256 = request.headers.first(name: "x-amz-content-sha256")
        XCTAssertEqual(contentSha256, bodyHash)
    }
    
    func testSignRequestWithUnsignedPayload() throws {
        let signer = AWSV4Signer(accessKey: testAccessKey, secretKey: testSecretKey, region: testRegion)
        let url = URL(string: "https://bucket.s3.amazonaws.com/object")!
        
        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = .PUT
        
        signer.sign(
            request: &request,
            url: url,
            method: "PUT",
            bodyHash: "UNSIGNED-PAYLOAD",
            headers: [:],
            now: fixedTimestamp
        )
        
        let contentSha256 = request.headers.first(name: "x-amz-content-sha256")
        XCTAssertEqual(contentSha256, "UNSIGNED-PAYLOAD")
    }
    
    // MARK: - Region Tests
    
    func testSignRequestWithDifferentRegions() throws {
        let regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-northeast-1", "sa-east-1"]
        
        for region in regions {
            let signer = AWSV4Signer(accessKey: testAccessKey, secretKey: testSecretKey, region: region)
            let url = URL(string: "https://bucket.s3.\(region).amazonaws.com/object")!
            
            var request = HTTPClientRequest(url: url.absoluteString)
            request.method = .GET
            
            signer.sign(
                request: &request,
                url: url,
                method: "GET",
                bodyHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                headers: [:],
                now: fixedTimestamp
            )
            
            let authHeader = request.headers.first(name: "Authorization")!
            XCTAssertTrue(authHeader.contains(region), "Auth header should contain region \(region)")
        }
    }
    
    // MARK: - Timestamp Tests
    
    func testSignRequestWithDifferentTimestamps() throws {
        let signer = AWSV4Signer(accessKey: testAccessKey, secretKey: testSecretKey, region: testRegion)
        let url = URL(string: "https://bucket.s3.amazonaws.com/object")!
        
        // Test different dates
        let dates = [
            Date(timeIntervalSince1970: 0),           // 1970-01-01
            Date(timeIntervalSince1970: 1000000000),  // 2001-09-09
            Date(timeIntervalSince1970: 1700000000),  // 2023-11-14
        ]
        
        for date in dates {
            var request = HTTPClientRequest(url: url.absoluteString)
            request.method = .GET
            
            signer.sign(
                request: &request,
                url: url,
                method: "GET",
                bodyHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                headers: [:],
                now: date
            )
            
            XCTAssertNotNil(request.headers.first(name: "x-amz-date"))
            XCTAssertNotNil(request.headers.first(name: "Authorization"))
        }
    }
    
    // MARK: - Path Tests
    
    func testSignRequestWithDifferentPaths() throws {
        let signer = AWSV4Signer(accessKey: testAccessKey, secretKey: testSecretKey, region: testRegion)
        
        let paths = [
            "/",
            "/object",
            "/folder/object.txt",
            "/deep/nested/path/to/file.json",
            "/file%20with%20spaces.txt"
        ]
        
        for path in paths {
            let url = URL(string: "https://bucket.s3.amazonaws.com\(path)")!
            
            var request = HTTPClientRequest(url: url.absoluteString)
            request.method = .GET
            
            signer.sign(
                request: &request,
                url: url,
                method: "GET",
                bodyHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                headers: [:],
                now: fixedTimestamp
            )
            
            XCTAssertNotNil(request.headers.first(name: "Authorization"), "Auth should be present for path: \(path)")
        }
    }
    
    func testSignRequestWithQueryParameters() throws {
        let signer = AWSV4Signer(accessKey: testAccessKey, secretKey: testSecretKey, region: testRegion)
        let url = URL(string: "https://bucket.s3.amazonaws.com/?list-type=2&prefix=folder/&delimiter=/")!
        
        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = .GET
        
        signer.sign(
            request: &request,
            url: url,
            method: "GET",
            bodyHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            headers: [:],
            now: fixedTimestamp
        )
        
        XCTAssertNotNil(request.headers.first(name: "Authorization"))
    }
    
    // MARK: - Determinism Tests
    
    func testSignRequestIsDeterministic() throws {
        let signer = AWSV4Signer(accessKey: testAccessKey, secretKey: testSecretKey, region: testRegion)
        let url = URL(string: "https://bucket.s3.amazonaws.com/object")!
        
        // Sign the same request multiple times
        var signatures: [String] = []
        
        for _ in 1...5 {
            var request = HTTPClientRequest(url: url.absoluteString)
            request.method = .GET
            
            signer.sign(
                request: &request,
                url: url,
                method: "GET",
                bodyHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                headers: [:],
                now: fixedTimestamp
            )
            
            if let auth = request.headers.first(name: "Authorization") {
                signatures.append(auth)
            }
        }
        
        // All signatures should be identical (deterministic)
        XCTAssertTrue(signatures.allSatisfy { $0 == signatures[0] })
    }
    
    func testDifferentCredentialsProduceDifferentSignatures() throws {
        let signer1 = AWSV4Signer(accessKey: "KEY1", secretKey: "SECRET1", region: testRegion)
        let signer2 = AWSV4Signer(accessKey: "KEY2", secretKey: "SECRET2", region: testRegion)
        
        let url = URL(string: "https://bucket.s3.amazonaws.com/object")!
        
        var request1 = HTTPClientRequest(url: url.absoluteString)
        request1.method = .GET
        
        var request2 = HTTPClientRequest(url: url.absoluteString)
        request2.method = .GET
        
        signer1.sign(
            request: &request1,
            url: url,
            method: "GET",
            bodyHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            headers: [:],
            now: fixedTimestamp
        )
        
        signer2.sign(
            request: &request2,
            url: url,
            method: "GET",
            bodyHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            headers: [:],
            now: fixedTimestamp
        )
        
        let auth1 = request1.headers.first(name: "Authorization")!
        let auth2 = request2.headers.first(name: "Authorization")!
        
        XCTAssertNotEqual(auth1, auth2)
    }
    
    // MARK: - Header Format Tests
    
    func testAuthorizationHeaderFormat() throws {
        let signer = AWSV4Signer(accessKey: testAccessKey, secretKey: testSecretKey, region: testRegion)
        let url = URL(string: "https://bucket.s3.amazonaws.com/object")!
        
        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = .GET
        
        signer.sign(
            request: &request,
            url: url,
            method: "GET",
            bodyHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            headers: [:],
            now: fixedTimestamp
        )
        
        let authHeader = request.headers.first(name: "Authorization")!
        
        // Check format: AWS4-HMAC-SHA256 Credential=.../date/region/s3/aws4_request, SignedHeaders=..., Signature=...
        XCTAssertTrue(authHeader.hasPrefix("AWS4-HMAC-SHA256 Credential="))
        XCTAssertTrue(authHeader.contains("SignedHeaders="))
        XCTAssertTrue(authHeader.contains("Signature="))
        XCTAssertTrue(authHeader.contains("/s3/aws4_request"))
        
        // Signed headers should include required headers
        XCTAssertTrue(authHeader.contains("host"))
        XCTAssertTrue(authHeader.contains("x-amz-date"))
        XCTAssertTrue(authHeader.contains("x-amz-content-sha256"))
    }
    
    func testDateHeaderFormat() throws {
        let signer = AWSV4Signer(accessKey: testAccessKey, secretKey: testSecretKey, region: testRegion)
        let url = URL(string: "https://bucket.s3.amazonaws.com/object")!
        
        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = .GET
        
        // Use a specific date
        let date = Date(timeIntervalSince1970: 1609459200) // 2021-01-01T00:00:00Z
        
        signer.sign(
            request: &request,
            url: url,
            method: "GET",
            bodyHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            headers: [:],
            now: date
        )
        
        let dateHeader = request.headers.first(name: "x-amz-date")!
        
        // Format should be: YYYYMMDDTHHMMSSZ
        XCTAssertTrue(dateHeader.hasPrefix("20210101T"))
        XCTAssertTrue(dateHeader.hasSuffix("Z"))
        XCTAssertEqual(dateHeader.count, 16)
    }
    
    // MARK: - AWS URI Encoding Tests
    
    func testAWSURIEncodingUnreservedCharacters() {
        // Unreserved characters should NOT be encoded
        let unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
        XCTAssertEqual(unreserved.awsURIEncoded(), unreserved)
    }
    
    func testAWSURIEncodingReservedCharacters() {
        // Reserved characters should be encoded
        XCTAssertEqual("/".awsURIEncoded(), "%2F")
        XCTAssertEqual("?".awsURIEncoded(), "%3F")
        XCTAssertEqual("=".awsURIEncoded(), "%3D")
        XCTAssertEqual("&".awsURIEncoded(), "%26")
        XCTAssertEqual(":".awsURIEncoded(), "%3A")
        XCTAssertEqual("@".awsURIEncoded(), "%40")
        XCTAssertEqual("+".awsURIEncoded(), "%2B")
        XCTAssertEqual(" ".awsURIEncoded(), "%20")
    }
    
    func testAWSURIEncodingUnicodeCharacters() {
        // Unicode characters should be encoded
        XCTAssertEqual("é".awsURIEncoded(), "%C3%A9")
        XCTAssertEqual("文".awsURIEncoded(), "%E6%96%87")
        XCTAssertEqual("🚀".awsURIEncoded(), "%F0%9F%9A%80")
        XCTAssertEqual("ファイル".awsURIEncoded(), "%E3%83%95%E3%82%A1%E3%82%A4%E3%83%AB")
        XCTAssertEqual("файл".awsURIEncoded(), "%D1%84%D0%B0%D0%B9%D0%BB")
    }
    
    func testAWSPathEncodingPreservesSlashes() {
        // Path encoding should preserve forward slashes
        XCTAssertEqual("folder/subfolder/file.txt".awsPathEncoded(), "folder/subfolder/file.txt")
        XCTAssertEqual("/root/folder/file".awsPathEncoded(), "/root/folder/file")
    }
    
    func testAWSPathEncodingWithUnicode() {
        // Path encoding should encode Unicode but preserve slashes
        XCTAssertEqual("folder/文件.txt".awsPathEncoded(), "folder/%E6%96%87%E4%BB%B6.txt")
        XCTAssertEqual("/dossier/fichier-français.txt".awsPathEncoded(), "/dossier/fichier-fran%C3%A7ais.txt")
        XCTAssertEqual("путь/файл.txt".awsPathEncoded(), "%D0%BF%D1%83%D1%82%D1%8C/%D1%84%D0%B0%D0%B9%D0%BB.txt")
    }
    
    func testAWSPathEncodingWithSpaces() {
        // Spaces should be encoded as %20 (not +)
        XCTAssertEqual("my file.txt".awsPathEncoded(), "my%20file.txt")
        XCTAssertEqual("folder name/file name.txt".awsPathEncoded(), "folder%20name/file%20name.txt")
    }
    
    func testAWSQueryEncodingEncodesSlashes() {
        // Query encoding should encode forward slashes
        XCTAssertEqual("prefix/value".awsQueryEncoded(), "prefix%2Fvalue")
        XCTAssertEqual("folder1/".awsQueryEncoded(), "folder1%2F")
    }
    
    func testAWSQueryEncodingWithSpecialCharacters() {
        XCTAssertEqual("name=value".awsQueryEncoded(), "name%3Dvalue")
        XCTAssertEqual("hello world".awsQueryEncoded(), "hello%20world")
        XCTAssertEqual("a+b".awsQueryEncoded(), "a%2Bb")
    }
    
    func testAWSEncodingRoundTrip() {
        // Test that encoding can be decoded back (using percent decoding)
        let testStrings = [
            "simple",
            "with space",
            "unicode-文件",
            "emoji-🚀",
            "français",
            "path/to/file",
            "name=value&other=test"
        ]
        
        for original in testStrings {
            let encoded = original.awsURIEncoded()
            let decoded = encoded.removingPercentEncoding
            XCTAssertEqual(decoded, original, "Round-trip failed for: \(original)")
        }
    }
    
    func testAWSPathEncodingEmptyString() {
        XCTAssertEqual("".awsPathEncoded(), "")
        XCTAssertEqual("".awsURIEncoded(), "")
        XCTAssertEqual("".awsQueryEncoded(), "")
    }
    
    func testAWSPathEncodingOnlySlashes() {
        XCTAssertEqual("/".awsPathEncoded(), "/")
        XCTAssertEqual("//".awsPathEncoded(), "//")
        XCTAssertEqual("/a/b/c/".awsPathEncoded(), "/a/b/c/")
    }
    
    func testAWSEncodingMixedContent() {
        // Real-world example: a file path with various characters
        let path = "/bucket/folder/My Document (2024)-日本語.pdf"
        let encoded = path.awsPathEncoded()
        
        // Should preserve slashes but encode spaces, parentheses, and Unicode
        XCTAssertTrue(encoded.contains("/bucket/folder/"))
        XCTAssertTrue(encoded.contains("%20"))  // Space
        XCTAssertTrue(encoded.contains("%28"))  // (
        XCTAssertTrue(encoded.contains("%29"))  // )
        XCTAssertFalse(encoded.contains(" "))   // No raw spaces
    }
}
