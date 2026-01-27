import XCTest
import AsyncHTTPClient
import NIOHTTP1
@testable import CybS3Lib

final class AWSV4SignerTests: XCTestCase {
    
    func testSignRequest() throws {
        // Test vectors could be taken from AWS documentation, but for now we verify basic structure
        
        let accessKey = "AKIAIOSFODNN7EXAMPLE"
        let secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        let region = "us-east-1"
        
        let signer = AWSV4Signer(accessKey: accessKey, secretKey: secretKey, region: region)
        
        let url = URL(string: "https://examplebucket.s3.amazonaws.com/test.txt")!
        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = .GET
        
        let now = Date(timeIntervalSince1970: 1369353600) // 2013-05-24T00:00:00Z
        
        signer.sign(
            request: &request,
            url: url,
            method: "GET",
            bodyHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // Empty hash
            headers: [:],
            now: now
        )
        
        // Check Headers
        XCTAssertNotNil(request.headers.first(name: "Authorization"))
        XCTAssertNotNil(request.headers.first(name: "x-amz-date"))
        XCTAssertNotNil(request.headers.first(name: "x-amz-content-sha256"))
        
        let authHeader = request.headers.first(name: "Authorization")!
        // AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, ...
        
        XCTAssertTrue(authHeader.hasPrefix("AWS4-HMAC-SHA256"))
        XCTAssertTrue(authHeader.contains("Credential=\(accessKey)/20130524/\(region)/s3/aws4_request"))
        XCTAssertTrue(authHeader.contains("Signature="))
        
        let dateHeader = request.headers.first(name: "x-amz-date")!
        XCTAssertEqual(dateHeader, "20130524T000000Z")
    }
}
