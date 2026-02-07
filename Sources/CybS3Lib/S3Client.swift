import Foundation
import Crypto
import AsyncHTTPClient
import Logging
import NIO
import NIOHTTP1
import NIOFoundationCompat

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(FoundationXML)
import FoundationXML
#endif

// MARK: - S3 Error Types

/// Errors that can occur during S3 operations.
public enum S3Error: Error, LocalizedError, Equatable {
    /// The provided URL or endpoint was invalid.
    case invalidURL
    /// Authentication with S3 failed (e.g., invalid keys).
    case authenticationFailed
    /// The request failed with details from S3.
    case requestFailed(status: Int, code: String?, message: String?)
    /// Legacy request failed for backward compatibility.
    case requestFailedLegacy(String)
    /// The response from S3 was invalid or could not be parsed.
    case invalidResponse
    /// The specified bucket was not found.
    case bucketNotFound
    /// The specified object was not found.
    case objectNotFound
    /// Access to the local file system failed.
    case fileAccessFailed
    /// Access denied to the resource.
    case accessDenied(resource: String?)
    /// The bucket is not empty (for delete operations).
    case bucketNotEmpty
    
    public var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "❌ Invalid URL: Check your endpoint configuration."
        case .authenticationFailed:
            return "❌ Authentication Failed: Check your Access Key and Secret Key."
        case .requestFailed(let status, let code, let message):
            var desc = "❌ Request Failed (HTTP \(status))"
            if let code = code { desc += "\n   Code: \(code)" }
            if let message = message { desc += "\n   Message: \(message)" }
            return desc
        case .requestFailedLegacy(let msg):
            return "❌ Request Failed: \(msg)"
        case .invalidResponse:
            return "❌ Invalid Response: The server returned an unexpected response."
        case .bucketNotFound:
            return "❌ Bucket Not Found: Specify a bucket with --bucket or select a vault."
        case .objectNotFound:
            return "❌ Object Not Found: The specified key does not exist."
        case .fileAccessFailed:
            return "❌ File Access Failed: Check file permissions and path."
        case .accessDenied(let resource):
            if let resource = resource {
                return "❌ Access Denied: You don't have permission to access '\(resource)'."
            }
            return "❌ Access Denied: Check your credentials and bucket policies."
        case .bucketNotEmpty:
            return "❌ Bucket Not Empty: Delete all objects before deleting the bucket."
        }
    }
    
    /// Provides actionable suggestions for resolving the error.
    public var suggestions: [String] {
        switch self {
        case .authenticationFailed:
            return [
                "Verify your access key and secret key are correct",
                "Check if your credentials have the necessary S3 permissions",
                "Ensure the correct region is specified"
            ]
        case .bucketNotFound:
            return [
                "Verify the bucket name is correct",
                "Check if the bucket exists in the specified region",
                "Ensure you have permission to access the bucket"
            ]
        case .objectNotFound:
            return [
                "Verify the object key is correct",
                "Check if the object exists in the bucket",
                "Ensure you have permission to read the object"
            ]
        case .accessDenied:
            return [
                "Check your AWS credentials and permissions",
                "Verify bucket policies allow your operations",
                "Ensure you're using the correct region"
            ]
        case .invalidURL:
            return [
                "Check your endpoint URL format",
                "Use https:// for secure connections",
                "Verify the endpoint is reachable"
            ]
        case .requestFailed(let status, _, _):
            if status == 429 {
                return [
                    "Too many requests - wait and retry",
                    "Consider reducing request frequency",
                    "Check AWS service limits"
                ]
            } else if status >= 500 {
                return [
                    "Server error - retry the operation",
                    "Check AWS service status",
                    "Try again later"
                ]
            } else {
                return [
                    "Check your request parameters",
                    "Verify permissions and credentials",
                    "Review AWS documentation for this error code"
                ]
            }
        case .bucketNotEmpty:
            return [
                "Delete all objects in the bucket first",
                "Use recursive delete if needed",
                "Check for incomplete multipart uploads"
            ]
        case .fileAccessFailed:
            return [
                "Check file permissions",
                "Verify the file path exists",
                "Ensure write access to the directory"
            ]
        case .invalidResponse:
            return [
                "Check network connectivity",
                "Verify endpoint configuration",
                "Try the operation again"
            ]
        case .requestFailedLegacy:
            return [
                "Check your network connection",
                "Verify credentials and permissions",
                "Try the operation again"
            ]
        }
    }
}

/// Helper to parse S3 XML error responses.
struct S3ErrorParser {
    /// Parses an S3 XML error response and returns an appropriate S3Error.
    static func parse(data: Data, status: Int) -> S3Error {
        guard !data.isEmpty else {
            return .requestFailed(status: status, code: nil, message: "Empty response")
        }
        do {
            let xml = try XMLDocument(data: data)
            guard let root = try? xml.rootElement() else {
                throw NSError(domain: "XML", code: 0, userInfo: nil)
            }
            let code = (try? root.nodes(forXPath: "Code").first?.stringValue) ?? (try? xml.nodes(forXPath: "//Error/Code").first?.stringValue)
            let message = (try? root.nodes(forXPath: "Message").first?.stringValue) ?? (try? xml.nodes(forXPath: "//Error/Message").first?.stringValue)
            
            // Map common S3 error codes to specific errors
            switch code {
            case "AccessDenied":
                return .accessDenied(resource: nil)
            case "NoSuchBucket":
                return .bucketNotFound
            case "NoSuchKey":
                return .objectNotFound
            case "BucketNotEmpty":
                return .bucketNotEmpty
            case "InvalidAccessKeyId", "SignatureDoesNotMatch":
                return .authenticationFailed
            default:
                return .requestFailed(status: status, code: code, message: message)
            }
        } catch {
            // If we can't parse XML, return generic error with raw data
            let rawMessage = String(data: data, encoding: .utf8)
            return .requestFailed(status: status, code: nil, message: rawMessage)
        }
    }
}

// MARK: - AWS URI Encoding

/// AWS S3 requires specific URI encoding rules that differ from standard URL encoding.
/// Per AWS documentation, the following characters should NOT be encoded:
/// - Unreserved characters: A-Z, a-z, 0-9, hyphen (-), underscore (_), period (.), tilde (~)
/// All other characters must be percent-encoded.
extension String {
    /// Encodes a string for use in AWS S3 URI paths.
    /// This follows AWS URI encoding rules where only unreserved characters are allowed.
    func awsURIEncoded() -> String {
        // AWS unreserved characters: A-Z a-z 0-9 - _ . ~
        var allowed = CharacterSet()
        allowed.insert(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~")
        return self.addingPercentEncoding(withAllowedCharacters: allowed) ?? self
    }
    
    /// Encodes a string for use in AWS S3 URI paths, preserving forward slashes.
    /// Use this for object keys that contain path separators.
    func awsPathEncoded() -> String {
        // Split by /, encode each segment, rejoin with /
        return self.split(separator: "/", omittingEmptySubsequences: false)
            .map { String($0).awsURIEncoded() }
            .joined(separator: "/")
    }
    
    /// Encodes a string for use in AWS S3 query parameter values.
    /// Forward slashes ARE encoded in query parameters.
    func awsQueryEncoded() -> String {
        return self.awsURIEncoded()
    }
}

/// Represents an S3 endpoint configuration.
public struct S3Endpoint: Sendable {
    /// The hostname of the S3 service (e.g., `s3.amazonaws.com`).
    public let host: String
    /// The port number (usually 443 for HTTPS or 80 for HTTP).
    public let port: Int
    /// Whether to use SSL/HTTPS.
    public let useSSL: Bool
    
    public init(host: String, port: Int, useSSL: Bool) {
        self.host = host
        self.port = port
        self.useSSL = useSSL
    }
    
    /// Returns "https" or "http" based on `useSSL`.
    public var scheme: String { useSSL ? "https" : "http" }
    
    /// Constructs a full URL from the endpoint components.
    public var url: URL? {
        var components = URLComponents()
        components.scheme = scheme
        components.host = host
        components.port = port
        return components.url
    }
}

// MARK: - AWS V4 Signer

/// Helper struct to generate AWS Signature Version 4 headers.
struct AWSV4Signer {
    let accessKey: String
    let secretKey: String
    let region: String
    let service: String = "s3"
    
    /// Signs an HTTP request according to AWS V4 signature requirements.
    ///
    /// - Parameters:
    ///   - request: The HTTPClientRequest to modify with signature headers.
    ///   - url: The full URL of the request.
    ///   - method: The HTTP method (GET, PUT, etc.).
    ///   - bodyHash: The SHA256 hash of the request body (hex string). Use "UNSIGNED-PAYLOAD" if payload signing is skipped.
    ///   - headers: Additional headers to include in the signature.
    ///   - now: The timestamp to use for signing (defaults to current Date).
    func sign(
        request: inout HTTPClientRequest,
        url: URL,
        method: String,
        bodyHash: String,
        headers: [String: String],
        now: Date = Date()
    ) {
        let timestamp = iso8601DateFormatter.string(from: now)
        let dateStamp = String(timestamp.prefix(8))
        
        // 1. Prepare Headers
        request.headers.add(name: "Host", value: url.host ?? "")
        request.headers.add(name: "x-amz-date", value: timestamp)
        request.headers.add(name: "x-amz-content-sha256", value: bodyHash)
        
        for (k, v) in headers {
            request.headers.add(name: k, value: v)
        }
        
        // 2. Canonical Request
        // Headers for signing need to be sorted and lowercase
        var signedHeadersDict: [String: String] = [
            "host": url.host ?? "",
            "x-amz-date": timestamp,
            "x-amz-content-sha256": bodyHash
        ]
        
        for (k, v) in headers {
            signedHeadersDict[k.lowercased()] = v.trimmingCharacters(in: .whitespaces)
        }
        
        let signedHeadersKeys = signedHeadersDict.keys.sorted()
        let signedHeadersString = signedHeadersKeys.joined(separator: ";")
        
        let canonicalHeaders = signedHeadersKeys.map { key in
            "\(key):\(signedHeadersDict[key]!)"
        }.joined(separator: "\n")
        
        // Canonical Query - must use AWS-specific encoding
        // Use percentEncodedQuery to get the already-encoded query string,
        // then parse and re-sort it (since it's already properly encoded)
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let canonicalQuery: String
        if let encodedQuery = components?.percentEncodedQuery, !encodedQuery.isEmpty {
            // Parse the already-encoded query string, sort by name, rejoin
            let pairs = encodedQuery.split(separator: "&").map { String($0) }
            let sortedPairs = pairs.sorted { pair1, pair2 in
                let name1 = pair1.split(separator: "=", maxSplits: 1).first ?? ""
                let name2 = pair2.split(separator: "=", maxSplits: 1).first ?? ""
                return name1 < name2
            }
            canonicalQuery = sortedPairs.joined(separator: "&")
        } else {
            canonicalQuery = ""
        }
        
        // Canonical Path - must use AWS-specific encoding
        // url.path returns decoded path, we need to re-encode it for signing
        let rawPath = url.path.isEmpty ? "/" : url.path
        let canonicalPath = rawPath.awsPathEncoded()
        
        let canonicalRequest = [
            method,
            canonicalPath,
            canonicalQuery,
            canonicalHeaders + "\n",
            signedHeadersString,
            bodyHash
        ].joined(separator: "\n")
        
        // 3. String to Sign
        let credentialScope = "\(dateStamp)/\(region)/\(service)/aws4_request"
        let stringToSign = [
            "AWS4-HMAC-SHA256",
            timestamp,
            credentialScope,
            SHA256.hash(data: Data(canonicalRequest.utf8)).hexString
        ].joined(separator: "\n")
        
        // 4. Signature
        let signingKey = getSignatureKey(secret: secretKey, dateStamp: dateStamp, region: region, service: service)
        let signature = Data(HMAC<SHA256>.authenticationCode(for: Data(stringToSign.utf8), using: signingKey)).hexString
        
        let authHeader = "AWS4-HMAC-SHA256 Credential=\(accessKey)/\(credentialScope), SignedHeaders=\(signedHeadersString), Signature=\(signature)"
        request.headers.add(name: "Authorization", value: authHeader)
    }
    
    private func getSignatureKey(secret: String, dateStamp: String, region: String, service: String) -> SymmetricKey {
        let kSecret = SymmetricKey(data: Data("AWS4\(secret)".utf8))
        let kDate = HMAC<SHA256>.authenticationCode(for: Data(dateStamp.utf8), using: kSecret)
        let kRegion = HMAC<SHA256>.authenticationCode(for: Data(region.utf8), using: SymmetricKey(data: kDate))
        let kService = HMAC<SHA256>.authenticationCode(for: Data(service.utf8), using: SymmetricKey(data: kRegion))
        let kSigning = HMAC<SHA256>.authenticationCode(for: Data("aws4_request".utf8), using: SymmetricKey(data: kService))
        return SymmetricKey(data: kSigning)
    }
}

// MARK: - S3 Client

/// An actor that manages S3 interactions such as listing buckets, objects, and uploading/downloading files.
/// It uses `AsyncHTTPClient` for networking and `AWSV4Signer` for authentication.
public actor S3Client {
    private let endpoint: S3Endpoint
    private let bucket: String?
    private let region: String
    private lazy var httpClient: HTTPClient = {
        // Configure HTTP client with optimized settings for performance
        var httpConfig = HTTPClient.Configuration()
        httpConfig.redirectConfiguration = .follow(max: 5, allowCycles: false)
        httpConfig.connectionPool = HTTPClient.Configuration.ConnectionPool(
            idleTimeout: .seconds(Int64(configuration.connectionIdleTimeout)),
            concurrentHTTP1ConnectionsPerHostSoftLimit: configuration.maxConnectionsPerHost
        )
        httpConfig.timeout = HTTPClient.Configuration.Timeout(
            connect: .seconds(Int64(configuration.connectTimeout)),
            read: .seconds(Int64(configuration.requestTimeout))
        )
        
        // Use multi-threaded event loop group for better concurrency
        #if os(macOS)
        let threadCount = min(System.coreCount, 16) // Cap at 16 threads on macOS
        #else
        let threadCount = System.coreCount
        #endif
        
        return HTTPClient(
            eventLoopGroupProvider: .shared(MultiThreadedEventLoopGroup(numberOfThreads: threadCount)),
            configuration: httpConfig
        )
    }()
    private let signer: AWSV4Signer
    private let logger: Logger
    private let configuration: Configuration
    
    /// Configuration options for the S3 client.
    public struct Configuration: Sendable {
        /// Maximum concurrent connections per host.
        public var maxConnectionsPerHost: Int
        /// Connection idle timeout in seconds.
        public var connectionIdleTimeout: Int
        /// Connect timeout in seconds.
        public var connectTimeout: Int
        /// Request timeout in seconds.
        public var requestTimeout: Int
        
        public init(
            maxConnectionsPerHost: Int = 8,
            connectionIdleTimeout: Int = 60,
            connectTimeout: Int = 10,
            requestTimeout: Int = 300
        ) {
            self.maxConnectionsPerHost = maxConnectionsPerHost
            self.connectionIdleTimeout = connectionIdleTimeout
            self.connectTimeout = connectTimeout
            self.requestTimeout = requestTimeout
        }
        
        /// Default configuration for general use.
        public static let `default` = Configuration()
        
        /// High-performance configuration for large transfers.
        public static let highPerformance = Configuration(
            maxConnectionsPerHost: 16,
            connectionIdleTimeout: 120,
            connectTimeout: 15,
            requestTimeout: 600
        )
    }
    
    /// Initializes a new S3Client.
    ///
    /// - Parameters:
    ///   - endpoint: The S3 endpoint configuration (host, port, ssl).
    ///   - accessKey: AWS Access Key ID.
    ///   - secretKey: AWS Secret Access Key.
    ///   - bucket: Optional bucket name to use as context for operations.
    ///   - region: AWS Region (default "us-east-1").
    ///   - configuration: Client configuration options.
    /// - Precondition: accessKey and secretKey must not be empty for authenticated operations.
    public init(
        endpoint: S3Endpoint,
        accessKey: String,
        secretKey: String,
        bucket: String? = nil,
        region: String = "us-east-1",
        configuration: Configuration = .default
    ) {
        // Validate inputs
        precondition(!endpoint.host.isEmpty, "S3 endpoint host cannot be empty")
        precondition(endpoint.port > 0 && endpoint.port <= 65535, "S3 endpoint port must be valid (1-65535)")
        
        self.endpoint = endpoint
        self.bucket = bucket?.isEmpty == true ? nil : bucket  // Normalize empty string to nil
        self.region = region.isEmpty ? "us-east-1" : region
        self.configuration = configuration
        
        self.signer = AWSV4Signer(accessKey: accessKey, secretKey: secretKey, region: region)
        self.logger = Logger(label: "com.cybs3.client")
    }
    
    /// Gracefully shuts down the HTTP client.
    /// Call this method when you're done using the S3Client to release resources.
    public func shutdown() async throws {
        try await httpClient.shutdown()
    }
    
    // MARK: - Request Building
    
    /// Builds and signs an HTTPClientRequest for S3.
    private func buildRequest(
        method: String,
        path: String = "/",
        queryItems: [URLQueryItem] = [],
        headers: [String: String] = [:],
        body: HTTPClientRequest.Body? = nil,
        bodyHash: String = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ) async throws -> HTTPClientRequest {
        guard let baseURL = endpoint.url else {
            throw S3Error.invalidURL
        }
        
        var urlComponents = URLComponents(url: baseURL, resolvingAgainstBaseURL: false)
        if let bucket = bucket {
            urlComponents?.host = "\(bucket).\(endpoint.host)"
        }
        
        // Encode path using AWS-compatible encoding
        // We use percentEncodedPath to ensure the URL contains properly encoded characters
        let normalizedPath = path.hasPrefix("/") ? path : "/" + path
        urlComponents?.percentEncodedPath = normalizedPath.awsPathEncoded()
        
        // Encode query items using AWS-compatible encoding
        if !queryItems.isEmpty {
            urlComponents?.percentEncodedQuery = queryItems
                .map { item in
                    let encodedName = item.name.awsQueryEncoded()
                    let encodedValue = (item.value ?? "").awsQueryEncoded()
                    return "\(encodedName)=\(encodedValue)"
                }
                .joined(separator: "&")
        }
        
        guard let url = urlComponents?.url else {
            throw S3Error.invalidURL
        }
        
        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = HTTPMethod(rawValue: method)
        if let body = body {
            request.body = body
        }
        
        signer.sign(
            request: &request,
            url: url,
            method: method,
            bodyHash: bodyHash,
            headers: headers
        )
        
        return request
    }
    
    /// Helper to handle S3 error responses.
    private func handleErrorResponse(_ response: HTTPClientResponse) async throws -> S3Error {
        let body = try await response.body.collect(upTo: 1024 * 1024)
        let data = Data(buffer: body)
        return S3ErrorParser.parse(data: data, status: Int(response.status.code))
    }
    
    // MARK: - Public API
    
    /// Lists all buckets owned by the authenticated sender.
    /// - Returns: An array of bucket names.
    public func listBuckets() async throws -> [String] {
        let request = try await buildRequest(method: "GET")
        
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        guard response.status == HTTPResponseStatus.ok else {
            throw try await handleErrorResponse(response)
        }
        
        let body = try await response.body.collect(upTo: 10 * 1024 * 1024)
        let data = Data(buffer: body)
        let xml = try XMLDocument(data: data)
        
        return try xml.nodes(forXPath: "//ListAllMyBucketsResult/Buckets/Bucket/Name")
            .compactMap { $0.stringValue }
    }
    
    /// Lists objects in the current bucket.
    ///
    /// - Parameters:
    ///   - prefix: Limits the response to keys that begin with the specified prefix.
    ///   - delimiter: A delimiter is a character you use to group keys.
    /// - Returns: An array of `S3Object`s.
    public func listObjects(prefix: String? = nil, delimiter: String? = nil, maxKeys: Int? = nil) async throws -> [S3Object] {
        guard bucket != nil else { throw S3Error.bucketNotFound }
        
        var objects: [S3Object] = []
        var isTruncated = true
        var continuationToken: String?
        
        let batchSize = 1000
        
        while isTruncated && (maxKeys == nil || objects.count < maxKeys!) {
            var queryItems: [URLQueryItem] = [
                URLQueryItem(name: "list-type", value: "2")
            ]
            if let prefix = prefix {
                queryItems.append(URLQueryItem(name: "prefix", value: prefix))
            }
            if let delimiter = delimiter {
                queryItems.append(URLQueryItem(name: "delimiter", value: delimiter))
            }
            let remaining = maxKeys.map { $0 - objects.count } ?? batchSize
            let requestBatchSize = min(batchSize, remaining)
            queryItems.append(URLQueryItem(name: "max-keys", value: String(requestBatchSize)))
            
            if let token = continuationToken {
                queryItems.append(URLQueryItem(name: "continuation-token", value: token))
            }
            
            let request = try await buildRequest(
                method: "GET",
                path: "/",
                queryItems: queryItems
            )
            
            let response = try await httpClient.execute(request, timeout: .seconds(30))
            guard response.status == HTTPResponseStatus.ok else {
                throw try await handleErrorResponse(response)
            }
            
            let body = try await response.body.collect(upTo: 20 * 1024 * 1024)
            let data = Data(buffer: body)
            let xml = try XMLDocument(data: data)
            
            let objectNodes = try xml.nodes(forXPath: "//*[local-name()='Contents']")
            for node in objectNodes {
                guard let key = (try? node.nodes(forXPath: "*[local-name()='Key']").first)?.stringValue,
                      let lastModified = (try? node.nodes(forXPath: "*[local-name()='LastModified']").first)?.stringValue,
                      let sizeString = (try? node.nodes(forXPath: "*[local-name()='Size']").first)?.stringValue,
                      let size = Int(sizeString) else {
                    print("DEBUG: Failed to parse object fields")
                    continue
                }
                
                let etag = (try? node.nodes(forXPath: "*[local-name()='ETag']").first)?.stringValue
                
                objects.append(S3Object(
                    key: key,
                    size: size,
                    lastModified: iso8601DateFormatter.date(from: lastModified) ?? Date(),
                    isDirectory: false,
                    etag: etag
                ))
            }
            
            let prefixNodes = try xml.nodes(forXPath: "//*[local-name()='CommonPrefixes']/*[local-name()='Prefix']")
            for node in prefixNodes {
                guard let prefix = node.stringValue else { continue }
                if !objects.contains(where: { $0.key == prefix && $0.isDirectory }) {
                    objects.append(S3Object(
                        key: prefix,
                        size: 0,
                        lastModified: Date(),
                        isDirectory: true,
                        etag: nil
                    ))
                }
            }
            
            if let truncatedNode = try? xml.nodes(forXPath: "//*[local-name()='IsTruncated']").first,
               truncatedNode.stringValue?.lowercased() == "true" {
                isTruncated = true
                if let nextTokenNode = try? xml.nodes(forXPath: "//*[local-name()='NextContinuationToken']").first {
                    continuationToken = nextTokenNode.stringValue
                } else {
                    isTruncated = false
                }
            } else {
                isTruncated = false
            }
        }
        return objects
    }
    
    /// Returns an asynchronous stream of data for the specified object.
    ///
    /// - Parameter key: The object key.
    /// - Returns: An `AsyncThrowingStream` supplying the object's data in chunks.
    public func getObjectStream(key: String) async throws -> AsyncThrowingStream<Data, Error> {
        guard bucket != nil else { throw S3Error.bucketNotFound }
        
        let path = key.hasPrefix("/") ? key : "/" + key
        let request = try await buildRequest(method: "GET", path: path)
        
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        guard response.status == HTTPResponseStatus.ok else {
            if response.status == HTTPResponseStatus.notFound {
                throw S3Error.objectNotFound
            }
            if response.status == HTTPResponseStatus.forbidden {
                throw S3Error.accessDenied(resource: key)
            }
            throw try await handleErrorResponse(response)
        }
        
        return AsyncThrowingStream { continuation in
            Task {
                do {
                    for try await buffer in response.body {
                        let data = Data(buffer: buffer)
                        continuation.yield(data)
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
        }
    }

    /// Gets the size of an object in bytes.
    ///
    /// - Parameter key: The object key.
    /// - Returns: The size in bytes, or nil if not found/determined.
    public func getObjectSize(key: String) async throws -> Int? {
        guard bucket != nil else { throw S3Error.bucketNotFound }
        
        let path = key.hasPrefix("/") ? key : "/" + key
        let request = try await buildRequest(method: "HEAD", path: path)
        
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        
        // Drain body if any (HEAD shouldn't have one but good practice)
        _ = try await response.body.collect(upTo: 1)
        
        guard response.status == HTTPResponseStatus.ok else {
            if response.status == HTTPResponseStatus.notFound {
                return nil
            }
            if response.status == HTTPResponseStatus.forbidden {
                throw S3Error.accessDenied(resource: key)
            }
            throw S3Error.requestFailed(status: Int(response.status.code), code: nil, message: "HEAD request failed")
        }
        
        if let contentLength = response.headers.first(name: "Content-Length"),
           let size = Int(contentLength) {
            return size
        }
        return nil
    }
    
    /// Downloads an object and returns its data.
    ///
    /// - Parameter key: The key of the object to download.
    /// - Returns: The object's data.
    /// - Throws: `S3Error` if the download fails.
    public func getObject(key: String) async throws -> Data {
        var data = Data()
        for try await chunk in try await getObjectStream(key: key) {
            data.append(chunk)
        }
        return data
    }
    
    /// Uploads an object from data.
    ///
    /// - Parameters:
    ///   - key: The key to assign to the object.
    ///   - data: The data to upload.
    ///   - metadata: Optional metadata to attach to the object.
    /// - Throws: `S3Error` if the upload fails.
    public func putObject(key: String, data: Data, metadata: [String: String]? = nil) async throws {
        let buffer = ByteBuffer(data: data)
        let stream = AsyncStream<ByteBuffer> { continuation in
            continuation.yield(buffer)
            continuation.finish()
        }
        try await putObject(key: key, stream: stream, length: Int64(data.count))
    }
    
    /// Uploads an object using a streaming body.
    ///
    /// - Parameters:
    ///   - key: The key to assign to the object.
    ///   - stream: An AsyncSequence of ByteBuffers providing the data.
    ///   - length: The total length of the upload (required for S3).
    /// - Throws: `S3Error` if the upload fails.
    /// - Note: Uses a 10-minute timeout for large uploads. For very large files, consider multipart upload.
    public func putObject<S: AsyncSequence & Sendable>(key: String, stream: S, length: Int64) async throws where S.Element == ByteBuffer {
        guard bucket != nil else { throw S3Error.bucketNotFound }
        guard !key.isEmpty else { throw S3Error.invalidURL }
        
        let path = key.hasPrefix("/") ? key : "/" + key
        
        let body = HTTPClientRequest.Body.stream(stream, length: .known(length))
        
        let request = try await buildRequest(
            method: "PUT",
            path: path,
            headers: ["Content-Type": "application/octet-stream"],
            body: body,
            bodyHash: "UNSIGNED-PAYLOAD"
        )
        
        // Use longer timeout for uploads based on file size (minimum 5 min, scale with size)
        let timeoutSeconds = max(300, Int64(length / (1024 * 1024)) * 2) // ~2s per MB, min 5 min
        let response = try await httpClient.execute(request, timeout: .seconds(timeoutSeconds))
        guard response.status == HTTPResponseStatus.ok else {
             throw try await handleErrorResponse(response)
        }
    }
    
    /// Deletes the specified object from the bucket.
    public func deleteObject(key: String) async throws {
        guard bucket != nil else { throw S3Error.bucketNotFound }
        
        let path = key.hasPrefix("/") ? key : "/" + key
        let request = try await buildRequest(method: "DELETE", path: path)
        
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        guard response.status == HTTPResponseStatus.noContent || response.status == HTTPResponseStatus.ok else {
            if response.status == HTTPResponseStatus.notFound {
                throw S3Error.objectNotFound
            }
            throw try await handleErrorResponse(response)
        }
    }
    
    /// Creates a new bucket using the current region.
    public func createBucket(name: String) async throws {
        // Location constraint
        // FIX: strict check for us-east-1 to avoid errors on AWS S3
        print("DEBUG: Creating bucket '\(name)' in region '\(region)'")
        let body: HTTPClientRequest.Body?
        let bodyHash: String
        let xmlStr: String?
        
        if region != "us-east-1" && region != "garage" {
            xmlStr = """
            <CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <LocationConstraint>\(region)</LocationConstraint>
            </CreateBucketConfiguration>
            """
            let data = Data(xmlStr!.utf8)
            bodyHash = data.sha256()
            body = HTTPClientRequest.Body.bytes(ByteBuffer(data: data))
            print("DEBUG: Sending LocationConstraint XML for region \(region)")
        } else if region == "garage" {
            // For garage, send empty CreateBucketConfiguration with xmlns
            xmlStr = """
            <CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></CreateBucketConfiguration>
            """
            let data = Data(xmlStr!.utf8)
            bodyHash = data.sha256()
            body = HTTPClientRequest.Body.bytes(ByteBuffer(data: data))
            print("DEBUG: Sending empty CreateBucketConfiguration XML for garage")
        } else {
             // For us-east-1, no body allowed for CreateBucket
            xmlStr = nil
            body = nil
            print("DEBUG: Not sending LocationConstraint XML for region \(region)")
            bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // Empty hash
        }
        
        let request = try await buildRequest(
            method: "PUT",
            path: "/",
            queryItems: [],
            headers: [:],
            body: body,
            bodyHash: bodyHash
        )
        
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        
        if response.status != HTTPResponseStatus.ok {
            let errBody = try await response.body.collect(upTo: 1024 * 1024)
            let data = Data(buffer: errBody)
            throw S3ErrorParser.parse(data: data, status: Int(response.status.code))
        }
    }
    
    /// Creates a bucket if it doesn't already exist.
    ///
    /// - Note: This method checks if the bucket exists first, and only creates it if it doesn't.
    public func createBucketIfNotExists() async throws {
        guard let bucketName = bucket else {
            throw S3Error.bucketNotFound
        }
        
        // Check if bucket exists by trying to list objects
        do {
            _ = try await listObjects(prefix: nil, delimiter: nil)
            // If we get here, bucket exists
            return
        } catch S3Error.objectNotFound {
            // Bucket doesn't exist, create it
            try await createBucket(name: bucketName)
        } catch S3Error.bucketNotFound {
            // Bucket doesn't exist, create it
            try await createBucket(name: bucketName)
        }
    }
    
    /// Deletes an empty bucket.
    ///
    /// - Parameter name: The name of the bucket to delete.
    /// - Note: The bucket must be empty before it can be deleted.
    public func deleteBucket(name: String) async throws {
        // Build request without bucket context (path-style for bucket operations)
        guard let baseURL = endpoint.url else {
            throw S3Error.invalidURL
        }
        
        var urlComponents = URLComponents(url: baseURL, resolvingAgainstBaseURL: false)
        urlComponents?.host = "\(name).\(endpoint.host)"
        urlComponents?.path = "/"
        
        guard let url = urlComponents?.url else {
            throw S3Error.invalidURL
        }
        
        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = .DELETE
        
        let bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // Empty body hash
        
        signer.sign(
            request: &request,
            url: url,
            method: "DELETE",
            bodyHash: bodyHash,
            headers: [:]
        )
        
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        
        // 204 No Content is success for DELETE bucket
        guard response.status == .noContent || response.status == .ok else {
            let errBody = try await response.body.collect(upTo: 1024 * 1024)
            let data = Data(buffer: errBody)
            throw S3ErrorParser.parse(data: data, status: Int(response.status.code))
        }
    }
    
    /// Copies an object within the same bucket or across buckets.
    ///
    /// - Parameters:
    ///   - sourceKey: The key of the source object.
    ///   - destKey: The key for the destination object.
    ///   - sourceBucket: Optional source bucket (defaults to current bucket).
    public func copyObject(sourceKey: String, destKey: String, sourceBucket: String? = nil) async throws {
        guard let currentBucket = bucket else { throw S3Error.bucketNotFound }
        
        let source = "/\(sourceBucket ?? currentBucket)/\(sourceKey)"
        let destPath = destKey.hasPrefix("/") ? destKey : "/" + destKey
        
        let request = try await buildRequest(
            method: "PUT",
            path: destPath,
            headers: ["x-amz-copy-source": source]
        )
        
        let response = try await httpClient.execute(request, timeout: .seconds(300))
        
        guard response.status == .ok else {
            throw try await handleErrorResponse(response)
        }
    }
    
    // MARK: - Multipart Upload API
    
    /// Represents a completed part in a multipart upload.
    public struct CompletedPart: Sendable {
        public let partNumber: Int
        public let etag: String
        
        public init(partNumber: Int, etag: String) {
            self.partNumber = partNumber
            self.etag = etag
        }
    }
    
    /// Initiates a multipart upload and returns the upload ID.
    ///
    /// - Parameter key: The object key for the upload.
    /// - Returns: The upload ID to use for subsequent part uploads.
    public func initiateMultipartUpload(key: String) async throws -> String {
        guard bucket != nil else { throw S3Error.bucketNotFound }
        
        let path = key.hasPrefix("/") ? key : "/" + key
        let request = try await buildRequest(
            method: "POST",
            path: path,
            queryItems: [URLQueryItem(name: "uploads", value: "")]
        )
        
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        
        guard response.status == .ok else {
            throw try await handleErrorResponse(response)
        }
        
        let body = try await response.body.collect(upTo: 1024 * 1024)
        let data = Data(buffer: body)
        let xml = try XMLDocument(data: data)
        
        guard let uploadId = try xml.nodes(forXPath: "//InitiateMultipartUploadResult/UploadId").first?.stringValue else {
            throw S3Error.invalidResponse
        }
        
        return uploadId
    }
    
    /// Uploads a part of a multipart upload.
    ///
    /// - Parameters:
    ///   - key: The object key.
    ///   - uploadId: The upload ID from `initiateMultipartUpload`.
    ///   - partNumber: The part number (1-10000).
    ///   - data: The data for this part.
    /// - Returns: The ETag for the uploaded part.
    public func uploadPart(key: String, uploadId: String, partNumber: Int, data: Data) async throws -> String {
        guard bucket != nil else { throw S3Error.bucketNotFound }
        
        let path = key.hasPrefix("/") ? key : "/" + key
        let bodyHash = data.sha256()
        
        let request = try await buildRequest(
            method: "PUT",
            path: path,
            queryItems: [
                URLQueryItem(name: "partNumber", value: String(partNumber)),
                URLQueryItem(name: "uploadId", value: uploadId)
            ],
            headers: ["Content-Type": "application/octet-stream"],
            body: .bytes(ByteBuffer(data: data)),
            bodyHash: bodyHash
        )
        
        let response = try await httpClient.execute(request, timeout: .seconds(300))
        
        guard response.status == .ok else {
            throw try await handleErrorResponse(response)
        }
        
        guard let etag = response.headers.first(name: "ETag") else {
            throw S3Error.invalidResponse
        }
        
        return etag
    }
    
    /// Completes a multipart upload.
    ///
    /// - Parameters:
    ///   - key: The object key.
    ///   - uploadId: The upload ID.
    ///   - parts: Array of completed parts with their ETags.
    public func completeMultipartUpload(key: String, uploadId: String, parts: [CompletedPart]) async throws {
        guard bucket != nil else { throw S3Error.bucketNotFound }
        
        let path = key.hasPrefix("/") ? key : "/" + key
        
        // Build XML body
        var xmlParts = "<CompleteMultipartUpload>"
        for part in parts.sorted(by: { $0.partNumber < $1.partNumber }) {
            xmlParts += "<Part><PartNumber>\(part.partNumber)</PartNumber><ETag>\(part.etag)</ETag></Part>"
        }
        xmlParts += "</CompleteMultipartUpload>"
        
        let bodyData = Data(xmlParts.utf8)
        let bodyHash = bodyData.sha256()
        
        let request = try await buildRequest(
            method: "POST",
            path: path,
            queryItems: [URLQueryItem(name: "uploadId", value: uploadId)],
            headers: ["Content-Type": "application/xml"],
            body: .bytes(ByteBuffer(data: bodyData)),
            bodyHash: bodyHash
        )
        
        let response = try await httpClient.execute(request, timeout: .seconds(60))
        
        guard response.status == .ok else {
            throw try await handleErrorResponse(response)
        }
    }
    
    /// Aborts a multipart upload.
    ///
    /// - Parameters:
    ///   - key: The object key.
    ///   - uploadId: The upload ID to abort.
    public func abortMultipartUpload(key: String, uploadId: String) async throws {
        guard bucket != nil else { throw S3Error.bucketNotFound }
        
        let path = key.hasPrefix("/") ? key : "/" + key
        
        let request = try await buildRequest(
            method: "DELETE",
            path: path,
            queryItems: [URLQueryItem(name: "uploadId", value: uploadId)]
        )
        
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        
        guard response.status == .noContent || response.status == .ok else {
            throw try await handleErrorResponse(response)
        }
    }
    
    /// Uploads a large object using multipart upload.
    ///
    /// - Parameters:
    ///   - key: The object key.
    ///   - data: The data to upload.
    ///   - partSize: Size of each part (minimum 5MB, default 10MB).
    ///   - progress: Optional progress callback.
    public func putObjectMultipart(
        key: String,
        data: Data,
        partSize: Int = 10 * 1024 * 1024,
        progress: (@Sendable (Double) -> Void)? = nil
    ) async throws {
        let uploadId = try await initiateMultipartUpload(key: key)
        
        var completedParts: [CompletedPart] = []
        var offset = 0
        var partNumber = 1
        let totalSize = data.count
        
        do {
            while offset < totalSize {
                let end = min(offset + partSize, totalSize)
                let partData = data[offset..<end]
                
                let etag = try await uploadPart(
                    key: key,
                    uploadId: uploadId,
                    partNumber: partNumber,
                    data: Data(partData)
                )
                
                completedParts.append(CompletedPart(partNumber: partNumber, etag: etag))
                
                offset = end
                partNumber += 1
                
                progress?(Double(offset) / Double(totalSize))
            }
            
            try await completeMultipartUpload(key: key, uploadId: uploadId, parts: completedParts)
        } catch {
            // Abort on failure
            try? await abortMultipartUpload(key: key, uploadId: uploadId)
            throw error
        }
    }
}

// MARK: - AsyncSequence Extensions

extension S3Client {
    /// Returns an AsyncSequence that yields all objects in the bucket.
    ///
    /// - Parameters:
    ///   - prefix: Optional prefix to filter objects.
    ///   - delimiter: Optional delimiter for hierarchical listing.
    /// - Returns: An AsyncThrowingStream of S3Object instances.
    public func listObjects() -> AsyncThrowingStream<S3Object, Error> {
        AsyncThrowingStream { continuation in
            Task {
                do {
                    // For streaming, we need to implement pagination manually
                    // This is a simplified version that gets all objects at once
                    let objects = try await listObjects(prefix: nil, delimiter: nil)
                    for object in objects {
                        continuation.yield(object)
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
        }
    }
    
    /// Returns an AsyncSequence that yields all objects with a given prefix.
    ///
    /// - Parameter prefix: The prefix to filter objects.
    /// - Returns: An AsyncThrowingStream of S3Object instances.
    public func listObjects(prefix: String) -> AsyncThrowingStream<S3Object, Error> {
        AsyncThrowingStream { continuation in
            Task {
                do {
                    // For streaming, we need to implement pagination manually
                    // This is a simplified version that gets all objects at once
                    let objects = try await listObjects(prefix: prefix, delimiter: nil)
                    for object in objects {
                        continuation.yield(object)
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
        }
    }
}

// MARK: - Models

/// Represents an object stored in S3 or a directory prefix.
public struct S3Object: CustomStringConvertible, Equatable, Hashable, Sendable {
    /// The key (path) of the object.
    public let key: String
    
    /// The size of the object in bytes.
    public let size: Int
    
    /// The last modified date of the object.
    public let lastModified: Date
    
    /// Indicates if this object represents a directory (common prefix) in a delimited list.
    public let isDirectory: Bool
    
    /// The ETag of the object (usually MD5 hash).
    public let etag: String?
    
    public init(key: String, size: Int, lastModified: Date, isDirectory: Bool, etag: String? = nil) {
        self.key = key
        self.size = size
        self.lastModified = lastModified
        self.isDirectory = isDirectory
        self.etag = etag
    }
    
    public var description: String {
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
        
        return String(format: "%.1f %@", size, units[unitIndex])
    }
}

// MARK: - Extensions & Helpers

// Thread-safe ISO8601 date formatter
private enum ISO8601DateFormatterFactory {
    // Thread-local storage for date formatters to avoid contention
    private static let threadLocalFormatter = ThreadLocal<ISO8601DateFormatter>()
    
    static var formatter: ISO8601DateFormatter {
        if let existing = threadLocalFormatter.value {
            return existing
        }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withYear, .withMonth, .withDay, .withTime, .withTimeZone]
        threadLocalFormatter.value = formatter
        return formatter
    }
}

// Simple thread-local storage implementation
private final class ThreadLocal<T>: @unchecked Sendable {
    private var storage: [ObjectIdentifier: T] = [:]
    private let lock = CrossPlatformLock()
    
    var value: T? {
        get {
            lock.withLock {
                storage[ObjectIdentifier(Thread.current)]
            }
        }
        set {
            lock.withLock {
                storage[ObjectIdentifier(Thread.current)] = newValue
            }
        }
    }
}

private var iso8601DateFormatter: ISO8601DateFormatter {
    ISO8601DateFormatterFactory.formatter
}

extension Data {
    /// Computes the SHA256 hash of the data and returns it as a hex string.
    func sha256() -> String {
        let hash = SHA256.hash(data: self)
        return hash.map { String(format: "%02hhx", $0) }.joined()
    }
    
    /// Returns the data as a hex string.
    var hexString: String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

extension Digest {
    /// Returns the digest as a hex string.
     var hexString: String {
        return map { String(format: "%02hhx", $0) }.joined()
     }
}

extension String {
    /// Returns the string as UTF-8 data.
     var data: Data { Data(utf8) }
}

public struct FileHandleAsyncSequence: AsyncSequence, Sendable {
    public typealias Element = ByteBuffer
    
    public let fileHandle: FileHandle
    public let chunkSize: Int
    public let progress: (@Sendable (Int) -> Void)?
    
    public init(fileHandle: FileHandle, chunkSize: Int, progress: (@Sendable (Int) -> Void)?) {
        self.fileHandle = fileHandle
        self.chunkSize = chunkSize
        self.progress = progress
    }
    
    public struct AsyncIterator: AsyncIteratorProtocol {
        let fileHandle: FileHandle
        let chunkSize: Int
        let progress: (@Sendable (Int) -> Void)?
        
        public mutating func next() async throws -> ByteBuffer? {
            let handle = fileHandle
            let size = chunkSize
            let callback = progress
            
            return try await Task {
                let data = try handle.read(upToCount: size)
                guard let data = data, !data.isEmpty else {
                    return nil
                }
                callback?(data.count)
                return ByteBuffer(data: data)
            }.value
        }
    }
    
    public func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(fileHandle: fileHandle, chunkSize: chunkSize, progress: progress)
    }
}