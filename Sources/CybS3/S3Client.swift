import Foundation
import Crypto
import AsyncHTTPClient
import Logging
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(FoundationXML)
import FoundationXML
#endif
import NIOFoundationCompat
import NIOHTTP1
import NIO

enum S3Error: Error {
    case invalidURL
    case authenticationFailed
    case requestFailed(String)
    case invalidResponse
    case bucketNotFound
    case objectNotFound
}

struct S3Endpoint {
    let host: String
    let port: Int
    let useSSL: Bool
    
    var scheme: String { useSSL ? "https" : "http" }
    var url: URL? {
        var components = URLComponents()
        components.scheme = scheme
        components.host = host
        components.port = port
        return components.url
    }
}

actor S3Client {
    private let endpoint: S3Endpoint
    private let accessKey: String
    private let secretKey: String
    private let bucket: String?
    private let region: String
    private let httpClient: HTTPClient
    private let logger: Logger
    
    init(
        endpoint: S3Endpoint,
        accessKey: String,
        secretKey: String,
        bucket: String? = nil,
        region: String = "us-east-1"
    ) {
        self.endpoint = endpoint
        self.accessKey = accessKey
        self.secretKey = secretKey
        self.bucket = bucket
        self.region = region
        self.httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
        self.logger = Logger(label: "com.cybs3.client")
    }
    
    deinit {
        try? httpClient.syncShutdown()
    }
    
    // MARK: - Authentication
    
    private func sign(string: String, secretKey: String) -> String {
        let key = SymmetricKey(data: Data("AWS4\(secretKey)".utf8))
        let signature = HMAC<SHA256>.authenticationCode(for: Data(string.utf8), using: key)
        return Data(signature).map { String(format: "%02hhx", $0) }.joined()
    }
    
    private func generateSignatureKey(secretKey: String, dateStamp: String, region: String, service: String) -> SymmetricKey {
        let kDate = HMAC<SHA256>.authenticationCode(
            for: Data(dateStamp.utf8),
            using: SymmetricKey(data: Data("AWS4\(secretKey)".utf8))
        )
        let kRegion = HMAC<SHA256>.authenticationCode(
            for: Data(region.utf8),
            using: SymmetricKey(data: Data(kDate))
        )
        let kService = HMAC<SHA256>.authenticationCode(
            for: Data(service.utf8),
            using: SymmetricKey(data: Data(kRegion))
        )
        let kSigning = HMAC<SHA256>.authenticationCode(
            for: Data("aws4_request".utf8),
            using: SymmetricKey(data: Data(kService))
        )
        return SymmetricKey(data: Data(kSigning))
    }
    
    private func createCanonicalRequest(
        method: String,
        path: String,
        query: String = "",
        headers: [String: String],
        payloadHash: String
    ) -> String {
        let canonicalHeaders = headers
            .map { "\($0.key.lowercased()):\($0.value.trimmingCharacters(in: .whitespaces))" }
            .sorted()
            .joined(separator: "\n")
        
        let signedHeaders = headers
            .keys
            .map { $0.lowercased() }
            .sorted()
            .joined(separator: ";")
        
        return [
            method,
            path,
            query,
            canonicalHeaders + "\n",
            signedHeaders,
            payloadHash
        ].joined(separator: "\n")
    }
    
    private func createStringToSign(
        timestamp: String,
        region: String,
        canonicalRequest: String
    ) -> String {
        let dateStamp = String(timestamp.prefix(8))
        let canonicalRequestHash = SHA256.hash(data: Data(canonicalRequest.utf8))
            .map { String(format: "%02hhx", $0) }
            .joined()
        
        return [
            "AWS4-HMAC-SHA256",
            timestamp,
            "\(dateStamp)/\(region)/s3/aws4_request",
            canonicalRequestHash
        ].joined(separator: "\n")
    }
    
    // MARK: - Request Building
    
    private func buildRequest(
        method: String,
        path: String = "/",
        queryItems: [URLQueryItem] = [],
        headers: [String: String] = [:],
        body: Data? = nil
    ) async throws -> (HTTPClient.Request, String) {
        guard let baseURL = endpoint.url else {
            throw S3Error.invalidURL
        }
        
        var urlComponents = URLComponents(url: baseURL, resolvingAgainstBaseURL: false)
        if let bucket = bucket {
            urlComponents?.host = "\(bucket).\(endpoint.host)"
        }
        urlComponents?.path = path
        
        if !queryItems.isEmpty {
            urlComponents?.queryItems = queryItems
        }
        
        guard let url = urlComponents?.url else {
            throw S3Error.invalidURL
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = method
        
        let timestamp = iso8601DateFormatter.string(from: Date())
        let dateStamp = String(timestamp.prefix(8))
        
        var allHeaders = headers
        allHeaders["Host"] = url.host ?? endpoint.host
        allHeaders["x-amz-date"] = timestamp
        allHeaders["x-amz-content-sha256"] = body?.sha256() ?? "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        
        if body != nil {
            allHeaders["Content-Type"] = "application/octet-stream"
        }
        
        let canonicalRequest = createCanonicalRequest(
            method: method,
            path: url.path,
            query: url.query ?? "",
            headers: allHeaders,
            payloadHash: allHeaders["x-amz-content-sha256"]!
        )
        
        let stringToSign = createStringToSign(
            timestamp: timestamp,
            region: region,
            canonicalRequest: canonicalRequest
        )
        
        let signatureKey = generateSignatureKey(
            secretKey: secretKey,
            dateStamp: dateStamp,
            region: region,
            service: "s3"
        )
        
        let signature = HMAC<SHA256>.authenticationCode(
            for: Data(stringToSign.utf8),
            using: signatureKey
        ).map { String(format: "%02hhx", $0) }.joined()
        
        let authHeader = "AWS4-HMAC-SHA256 Credential=\(accessKey)/\(dateStamp)/\(region)/s3/aws4_request, SignedHeaders=\(allHeaders.keys.map { $0.lowercased() }.sorted().joined(separator: ";")), Signature=\(signature)"
        
        allHeaders["Authorization"] = authHeader
        
        var nioHeaders = HTTPHeaders()
        for (key, value) in allHeaders {
            nioHeaders.add(name: key, value: value)
        }
        
        var nioBody: HTTPClient.Body?
        if let body = body {
            nioBody = .bytes(body)
        }
        
        let nioRequest = try HTTPClient.Request(
            url: url.absoluteString,
            method: HTTPMethod(rawValue: method),
            headers: nioHeaders,
            body: nioBody
        )
        
        return (nioRequest, canonicalRequest)
    }
    
    // MARK: - Public API
    
    func listBuckets() async throws -> [String] {
        let (request, _) = try await buildRequest(method: "GET")
        
        let response = try await httpClient.execute(request: request).get()
        guard let body = response.body else {
            throw S3Error.invalidResponse
        }
        
        let data = Data(buffer: body)
        let xml = try XMLDocument(data: data)
        
        return try xml.nodes(forXPath: "//ListAllMyBucketsResult/Buckets/Bucket/Name")
            .compactMap { $0.stringValue }
    }
    
    func listObjects(prefix: String? = nil, delimiter: String? = nil) async throws -> [S3Object] {
        guard bucket != nil else {
            throw S3Error.bucketNotFound
        }
        
        var queryItems: [URLQueryItem] = []
        if let prefix = prefix {
            queryItems.append(URLQueryItem(name: "prefix", value: prefix))
        }
        if let delimiter = delimiter {
            queryItems.append(URLQueryItem(name: "delimiter", value: delimiter))
        }
        
        let (request, _) = try await buildRequest(
            method: "GET",
            path: "/",
            queryItems: queryItems
        )
        
        let response = try await httpClient.execute(request: request).get()
        guard let body = response.body else {
            throw S3Error.invalidResponse
        }
        
        let data = Data(buffer: body)
        let xml = try XMLDocument(data: data)
        
        var objects: [S3Object] = []
        
        // Parse objects
        let objectNodes = try xml.nodes(forXPath: "//ListBucketResult/Contents")
        for node in objectNodes {
            guard let key = (try? node.nodes(forXPath: "Key").first)?.stringValue,
                  let lastModified = (try? node.nodes(forXPath: "LastModified").first)?.stringValue,
                  let sizeString = (try? node.nodes(forXPath: "Size").first)?.stringValue,
                  let size = Int(sizeString) else {
                continue
            }
            
            objects.append(S3Object(
                key: key,
                size: size,
                lastModified: iso8601DateFormatter.date(from: lastModified) ?? Date(),
                isDirectory: false
            ))
        }
        
        // Parse prefixes (directories)
        let prefixNodes = try xml.nodes(forXPath: "//ListBucketResult/CommonPrefixes/Prefix")
        for node in prefixNodes {
            guard let prefix = node.stringValue else { continue }
            objects.append(S3Object(
                key: prefix,
                size: 0,
                lastModified: Date(),
                isDirectory: true
            ))
        }
        
        return objects
    }
    
    func getObject(key: String) async throws -> Data {
        guard bucket != nil else {
            throw S3Error.bucketNotFound
        }
        
        let (request, _) = try await buildRequest(
            method: "GET",
            path: "/\(key)"
        )
        
        let response = try await httpClient.execute(request: request).get()
        guard response.status == HTTPResponseStatus.ok else {
            throw S3Error.objectNotFound
        }
        
        guard let body = response.body else {
            throw S3Error.invalidResponse
        }
        
        return Data(buffer: body)
    }
    
    func putObject(key: String, data: Data) async throws {
        guard bucket != nil else {
            throw S3Error.bucketNotFound
        }
        
        let (request, _) = try await buildRequest(
            method: "PUT",
            path: "/\(key)",
            body: data
        )
        
        let response = try await httpClient.execute(request: request).get()
        guard response.status == HTTPResponseStatus.ok else {
            throw S3Error.requestFailed("Failed to upload object: \(response.status)")
        }
    }
    
    func deleteObject(key: String) async throws {
        guard bucket != nil else {
            throw S3Error.bucketNotFound
        }
        
        let (request, _) = try await buildRequest(
            method: "DELETE",
            path: "/\(key)"
        )
        
        let response = try await httpClient.execute(request: request).get()
        guard response.status == HTTPResponseStatus.noContent else {
            throw S3Error.requestFailed("Failed to delete object: \(response.status)")
        }
    }
    
    func createBucket(name: String) async throws {
        
        let body = """
        <CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <LocationConstraint>\(region)</LocationConstraint>
        </CreateBucketConfiguration>
        """.data(using: .utf8)
        
        let (request, _) = try await buildRequest(
            method: "PUT",
            path: "/",
            body: body
        )
        
        let response = try await httpClient.execute(request: request).get()
        guard response.status == HTTPResponseStatus.ok else {
            throw S3Error.requestFailed("Failed to create bucket: \(response.status)")
        }
    }
}

// MARK: - Models

struct S3Object: CustomStringConvertible {
    let key: String
    let size: Int
    let lastModified: Date
    let isDirectory: Bool
    
    var description: String {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        
        let sizeString: String
        if isDirectory {
            sizeString = "DIR"
        } else {
            sizeString = formatBytes(size)
        }
        
        return "\(dateFormatter.string(from: lastModified))  \(sizeString.padding(toLength: 10, withPad: " ", startingAt: 0))  \(key)"
    }
    
    private func formatBytes(_ bytes: Int) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var size = Double(bytes)
        var unitIndex = 0
        
        while size >= 1024 && unitIndex < units.count - 1 {
            size /= 1024
            unitIndex += 1
        }
        
        return String(format: "%.1f %s", size, units[unitIndex])
    }
}

// MARK: - Extensions

private var iso8601DateFormatter: ISO8601DateFormatter {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    return formatter
}

extension Data {
    func sha256() -> String {
        let hash = SHA256.hash(data: self)
        return hash.map { String(format: "%02hhx", $0) }.joined()
    }
}