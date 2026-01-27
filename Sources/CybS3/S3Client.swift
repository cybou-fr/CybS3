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
enum S3Error: Error {
    case invalidURL
    case authenticationFailed
    case requestFailed(String)
    case invalidResponse
    case bucketNotFound
    case objectNotFound
    case fileAccessFailed
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
        
        // Sort query items for signing
        if !queryItems.isEmpty {
            urlComponents?.queryItems = queryItems.sorted { $0.name < $1.name }
        }
        
        guard let url = urlComponents?.url else {
            throw S3Error.invalidURL
        }
        
        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = HTTPMethod(rawValue: method)
        
        let timestamp = iso8601DateFormatter.string(from: Date())
        let dateStamp = String(timestamp.prefix(8))
        
        var allHeaders = headers
        allHeaders["Host"] = url.host ?? endpoint.host
        allHeaders["x-amz-date"] = timestamp
        allHeaders["x-amz-content-sha256"] = bodyHash
        
        if body != nil {
            // Content-Type should be set by caller or defaulted, but we need to ensure it's signed if present
            // If caller didn't set it, we don't force it here unless we know for sure?
            // AWS S3 usually expects Content-Type for PUT
        }
        
        // Construct canonical query string
        let canonicalQueryString = urlComponents?.queryItems?
            .map { item in
                let encodedName = item.name.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? item.name
                let encodedValue = item.value?.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
                return "\(encodedName)=\(encodedValue)"
            }
            .joined(separator: "&") ?? ""

        // Canonical Path should be URL encoded
        // But for S3 signing, it's tricky.
        // For basic ASCII keys, it's the path.
        // Let's assume path is already properly encoded or simple for now.
        let canonicalPath = url.path.isEmpty ? "/" : url.path

        let canonicalRequest = createCanonicalRequest(
            method: method,
            path: canonicalPath,
            query: canonicalQueryString,
            headers: allHeaders,
            payloadHash: bodyHash
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
        
        let signedHeaders = allHeaders.keys.map { $0.lowercased() }.sorted().joined(separator: ";")
        let authHeader = "AWS4-HMAC-SHA256 Credential=\(accessKey)/\(dateStamp)/\(region)/s3/aws4_request, SignedHeaders=\(signedHeaders), Signature=\(signature)"
        
        allHeaders["Authorization"] = authHeader
        
        for (key, value) in allHeaders {
            request.headers.add(name: key, value: value)
        }
        
        if let body = body {
            request.body = body
        }
        
        return request
    }
    
    // MARK: - Public API
    
    func listBuckets() async throws -> [String] {
        let request = try await buildRequest(method: "GET")
        
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        guard response.status == HTTPResponseStatus.ok else {
            throw S3Error.requestFailed("Status: \(response.status)")
        }
        
        let body = try await response.body.collect(upTo: 10 * 1024 * 1024) // 10MB max for XML
        
        let data = Data(buffer: body)
        let xml = try XMLDocument(data: data)
        
        return try xml.nodes(forXPath: "//ListAllMyBucketsResult/Buckets/Bucket/Name")
            .compactMap { $0.stringValue }
    }
    
    func listObjects(prefix: String? = nil, delimiter: String? = nil) async throws -> [S3Object] {
        guard bucket != nil else {
            throw S3Error.bucketNotFound
        }
        
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
            
            // Handle V2 pagination (ContinuationToken)
            // Note: S3 ListObjects V2 is generally preferred.
            // But let's check if the previous implementation was V1 or V2?
            // "GET /" without list-type=2 is V1.
            // Let's switch to V2 for reliable pagination.
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
            
            let body = try await response.body.collect(upTo: 20 * 1024 * 1024) // 20MB buffer
            let data = Data(buffer: body)
            let xml = try XMLDocument(data: data)
            
            // Parse objects
            // V2 path: //ListBucketResult/Contents
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
                // Avoid duplicates if paginated and prefixes repeat (unlikely in V2 but valid)
                if !objects.contains(where: { $0.key == prefix && $0.isDirectory }) {
                    objects.append(S3Object(
                        key: prefix,
                        size: 0,
                        lastModified: Date(),
                        isDirectory: true
                    ))
                }
            }
            
            // Check truncation
            if let truncatedNode = try? xml.nodes(forXPath: "//ListBucketResult/IsTruncated").first,
               truncatedNode.stringValue?.lowercased() == "true" {
                isTruncated = true
                if let nextTokenNode = try? xml.nodes(forXPath: "//ListBucketResult/NextContinuationToken").first {
                    continuationToken = nextTokenNode.stringValue
                } else {
                    // Should not happen in V2 if truncated
                    isTruncated = false
                }
            } else {
                isTruncated = false
            }
        }
        
        return objects
    }
    
    // Enhanced getObject returning AsyncThrowingStream
    func getObjectStream(key: String) async throws -> AsyncThrowingStream<Data, Error> {
        guard bucket != nil else {
            throw S3Error.bucketNotFound
        }
        
        let path = key.hasPrefix("/") ? key : "/" + key
        let request = try await buildRequest(
            method: "GET",
            path: path
        )
        
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
    
    // Legacy support for backward compatibility if needed, or convenience
    func getObject(key: String) async throws -> Data {
        var data = Data()
        for try await chunk in try await getObjectStream(key: key) {
            data.append(chunk)
        }
        return data
    }
    
    // Streaming Put using URLs (Files)
    func putObject(key: String, fileURL: URL, progress: (@Sendable (Int) -> Void)? = nil) async throws {
        guard bucket != nil else { throw S3Error.bucketNotFound }
        
        let fileHandle = try FileHandle(forReadingFrom: fileURL)
        let fileSize = try FileManager.default.attributesOfItem(atPath: fileURL.path)[.size] as? Int64 ?? 0
        
        // Calculate SHA256 of the file for signing?
        // S3 requires x-amz-content-sha256 header.
        // For streaming (UNSIGNED-PAYLOAD), we can use "UNSIGNED-PAYLOAD" as the hash value.
        // This is safe for HTTPS.
        
        let path = key.hasPrefix("/") ? key : "/" + key
        
        // We use a stream body
        // Note: AHC requires AsyncSequence of ByteBuffers.
        
        let asyncBytes = FileHandleAsyncSequence(fileHandle: fileHandle, chunkSize: 64 * 1024, progress: progress)
        let body = HTTPClientRequest.Body.stream(asyncBytes, length: .known(Int64(fileSize)))
        
        let request = try await buildRequest(
            method: "PUT",
            path: path,
            headers: ["Content-Type": "application/octet-stream"],
            body: body,
            bodyHash: "UNSIGNED-PAYLOAD" // Important for streaming without buffering entire file
        )
        
        let response = try await httpClient.execute(request, timeout: .seconds(300)) // 5 minutes timeout for upload
        guard response.status == HTTPResponseStatus.ok else {
             throw S3Error.requestFailed("Failed to upload object: \(response.status)")
        }
    }
    
    // Buffer Put for small data
    func putObject(key: String, data: Data) async throws {
        guard bucket != nil else { throw S3Error.bucketNotFound }
        
        let path = key.hasPrefix("/") ? key : "/" + key
        
        let bodyHash = data.sha256()
        let body = HTTPClientRequest.Body.bytes(ByteBuffer(data: data))
        
        let request = try await buildRequest(
            method: "PUT",
            path: path,
            headers: ["Content-Type": "application/octet-stream"],
            body: body,
            bodyHash: bodyHash
        )
        
        let response = try await httpClient.execute(request, timeout: .seconds(60))
        guard response.status == HTTPResponseStatus.ok else {
             throw S3Error.requestFailed("Failed to upload object: \(response.status)")
        }
    }
    
    func deleteObject(key: String) async throws {
        guard bucket != nil else { throw S3Error.bucketNotFound }
        
        let path = key.hasPrefix("/") ? key : "/" + key
        let request = try await buildRequest( method: "DELETE", path: path)
        
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        guard response.status == HTTPResponseStatus.noContent else {
             throw S3Error.requestFailed("Failed to delete object: \(response.status)")
        }
    }
    
    func createBucket(name: String) async throws {
        // Location constraint
        let xmlStr = """
        <CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <LocationConstraint>\(region)</LocationConstraint>
        </CreateBucketConfiguration>
        """
        let data = Data(xmlStr.utf8)
        let bodyHash = data.sha256()
        let body = HTTPClientRequest.Body.bytes(ByteBuffer(data: data))
        
        let request = try await buildRequest(
            method: "PUT",
            path: "/",
            body: body,
            bodyHash: bodyHash
        )
        
        let response = try await httpClient.execute(request, timeout: .seconds(30))
        
        if response.status != HTTPResponseStatus.ok {
             // Read body to see error
             let errBody = try? await response.body.collect(upTo: 1024 * 1024)
             let errStr = errBody.map { String(buffer: $0) } ?? ""
             throw S3Error.requestFailed("Failed to create bucket: \(response.status) \(errStr)")
        }
    }
}

// MARK: - Models

struct S3Object: CustomStringConvertible, Equatable, Hashable {
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

// MARK: - Extensions & Helpers

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


// Helper to convert FileHandle to AsyncSequence<ByteBuffer>
struct FileHandleAsyncSequence: AsyncSequence, Sendable {
    typealias Element = ByteBuffer
    
    let fileHandle: FileHandle
    let chunkSize: Int
    let progress: (@Sendable (Int) -> Void)?
    
    struct AsyncIterator: AsyncIteratorProtocol {
        let fileHandle: FileHandle
        let chunkSize: Int
        let progress: (@Sendable (Int) -> Void)?
        
        mutating func next() async throws -> ByteBuffer? {
            // Read data in background
            // Use local capture to avoid capturing mutating self in Task
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
    
    func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(fileHandle: fileHandle, chunkSize: chunkSize, progress: progress)
    }
}