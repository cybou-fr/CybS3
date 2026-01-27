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

// Re-export S3Object and S3Error for Commands.swift

/// Errors that can occur during S3 operations.
/// Errors that can occur during S3 operations.
public enum S3Error: Error {
    /// The provided URL or endpoint was invalid.
    case invalidURL
    /// Authentication with S3 failed (e.g., invalid keys).
    case authenticationFailed
    /// The request failed with a specific error message.
    case requestFailed(String)
    /// The response from S3 was invalid or could not be parsed.
    case invalidResponse
    /// The specified bucket was not found.
    case bucketNotFound
    /// The specified object was not found.
    case objectNotFound
    /// Access to the local file system failed.
    case fileAccessFailed
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
        
        // Canonical Query
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let canonicalQuery = components?.queryItems?
            .sorted { $0.name < $1.name }
            .map { item in
                let encodedName = item.name.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? item.name
                let encodedValue = item.value?.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
                return "\(encodedName)=\(encodedValue)"
            }
            .joined(separator: "&") ?? ""
            
        let canonicalPath = url.path.isEmpty ? "/" : url.path
        
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

// MARK: - S3 Client

/// An actor that manages S3 interactions such as listing buckets, objects, and uploading/downloading files.
/// It uses `AsyncHTTPClient` for networking and `AWSV4Signer` for authentication.
/// An actor that manages S3 interactions such as listing buckets, objects, and uploading/downloading files.
/// It uses `AsyncHTTPClient` for networking and `AWSV4Signer` for authentication.
public actor S3Client {
    private let endpoint: S3Endpoint
    private let bucket: String?
    private let region: String
    private let httpClient: HTTPClient
    private let signer: AWSV4Signer
    private let logger: Logger
    
    /// Initializes a new S3Client.
    ///
    /// - Parameters:
    ///   - endpoint: The S3 endpoint configuration (host, port, ssl).
    ///   - accessKey: AWS Access Key ID.
    ///   - secretKey: AWS Secret Access Key.
    ///   - bucket: Optional bucket name to use as context for operations.
    ///   - region: AWS Region (default "us-east-1").
    public init(
        endpoint: S3Endpoint,
        accessKey: String,
        secretKey: String,
        bucket: String? = nil,
        region: String = "us-east-1"
    ) {
        self.endpoint = endpoint
        self.bucket = bucket
        self.region = region
        self.httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
        self.signer = AWSV4Signer(accessKey: accessKey, secretKey: secretKey, region: region)
        self.logger = Logger(label: "com.cybs3.client")
    }
    
    deinit {
        try? httpClient.syncShutdown()
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
        
        // Ensure path starts with /
        urlComponents?.path = path.hasPrefix("/") ? path : "/" + path
        
        if !queryItems.isEmpty {
            urlComponents?.queryItems = queryItems
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
    
    // MARK: - Public API
    
    /// Lists all buckets owned by the authenticated sender.
    /// - Returns: An array of bucket names.
    public func listBuckets() async throws -> [String] {
        let request = try await buildRequest(method: "GET")
        
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        guard response.status == HTTPResponseStatus.ok else {
            throw S3Error.requestFailed("Status: \(response.status)")
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
    public func listObjects(prefix: String? = nil, delimiter: String? = nil) async throws -> [S3Object] {
        guard bucket != nil else { throw S3Error.bucketNotFound }
        
        var objects: [S3Object] = []
        var isTruncated = true
        var continuationToken: String?
        
        let batchSize = 1000
        
        while isTruncated {
            var queryItems: [URLQueryItem] = []
            if let prefix = prefix {
                queryItems.append(URLQueryItem(name: "prefix", value: prefix))
            }
            if let delimiter = delimiter {
                queryItems.append(URLQueryItem(name: "delimiter", value: delimiter))
            }
            queryItems.append(URLQueryItem(name: "max-keys", value: String(batchSize)))
            queryItems.append(URLQueryItem(name: "list-type", value: "2"))
            
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
                throw S3Error.requestFailed("Status: \(response.status)")
            }
            
            let body = try await response.body.collect(upTo: 20 * 1024 * 1024)
            let data = Data(buffer: body)
            let xml = try XMLDocument(data: data)
            
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
            
            let prefixNodes = try xml.nodes(forXPath: "//ListBucketResult/CommonPrefixes/Prefix")
            for node in prefixNodes {
                guard let prefix = node.stringValue else { continue }
                if !objects.contains(where: { $0.key == prefix && $0.isDirectory }) {
                    objects.append(S3Object(
                        key: prefix,
                        size: 0,
                        lastModified: Date(),
                        isDirectory: true
                    ))
                }
            }
            
            if let truncatedNode = try? xml.nodes(forXPath: "//ListBucketResult/IsTruncated").first,
               truncatedNode.stringValue?.lowercased() == "true" {
                isTruncated = true
                if let nextTokenNode = try? xml.nodes(forXPath: "//ListBucketResult/NextContinuationToken").first {
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
            throw S3Error.requestFailed("Status: \(response.status)")
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
    
    /// Uploads an object using a streaming body.
    ///
    /// - Parameters:
    ///   - key: The key to assign to the object.
    ///   - stream: An AsyncSequence of ByteBuffers providing the data.
    ///   - length: The total length of the upload (required for S3).
    public func putObject<S: AsyncSequence & Sendable>(key: String, stream: S, length: Int64) async throws where S.Element == ByteBuffer {
        guard bucket != nil else { throw S3Error.bucketNotFound }
        
        let path = key.hasPrefix("/") ? key : "/" + key
        
        let body = HTTPClientRequest.Body.stream(stream, length: .known(length))
        
        let request = try await buildRequest(
            method: "PUT",
            path: path,
            headers: ["Content-Type": "application/octet-stream"],
            body: body,
            bodyHash: "UNSIGNED-PAYLOAD"
        )
        
        let response = try await httpClient.execute(request, timeout: .seconds(300))
        guard response.status == HTTPResponseStatus.ok else {
             throw S3Error.requestFailed("Failed to upload object: \(response.status)")
        }
    }
    
    /// Deletes the specified object from the bucket.
    public func deleteObject(key: String) async throws {
        guard bucket != nil else { throw S3Error.bucketNotFound }
        
        let path = key.hasPrefix("/") ? key : "/" + key
        let request = try await buildRequest(method: "DELETE", path: path)
        
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        guard response.status == HTTPResponseStatus.noContent else {
             throw S3Error.requestFailed("Failed to delete object: \(response.status)")
        }
    }
    
    /// Creates a new bucket using the current region.
    public func createBucket(name: String) async throws {
        // Location constraint
        // FIX: strict check for us-east-1 to avoid errors on AWS S3
        let body: HTTPClientRequest.Body?
        let bodyHash: String
        let xmlStr: String?
        
        if region != "us-east-1" {
            xmlStr = """
            <CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <LocationConstraint>\(region)</LocationConstraint>
            </CreateBucketConfiguration>
            """
            let data = Data(xmlStr!.utf8)
            bodyHash = data.sha256()
            body = HTTPClientRequest.Body.bytes(ByteBuffer(data: data))
        } else {
             // For us-east-1, no body allowed for CreateBucket
            xmlStr = nil
            body = nil
            bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // Empty hash
        }
        
        let request = try await buildRequest(
            method: "PUT",
            path: "/",
            body: body,
            bodyHash: bodyHash
        )
        
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        
        if response.status != HTTPResponseStatus.ok {
             let errBody = try? await response.body.collect(upTo: 1024 * 1024)
             let errStr = errBody.map { String(buffer: $0) } ?? ""
             throw S3Error.requestFailed("Failed to create bucket: \(response.status) \(errStr)")
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
    
    public init(key: String, size: Int, lastModified: Date, isDirectory: Bool) {
        self.key = key
        self.size = size
        self.lastModified = lastModified
        self.isDirectory = isDirectory
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
        
        return String(format: "%.1f %s", size, units[unitIndex])
    }
}

// MARK: - Extensions & Helpers

private var iso8601DateFormatter: ISO8601DateFormatter {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    return formatter
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