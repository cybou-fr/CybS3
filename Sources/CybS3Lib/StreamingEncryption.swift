import Foundation
import Crypto
import NIO

public enum StreamingEncryptionError: Error, LocalizedError {
    case encryptionFailed
    case decryptionFailed
    case invalidData
    
    public var errorDescription: String? {
        switch self {
        case .encryptionFailed:
            return "❌ Encryption failed. The data could not be encrypted."
        case .decryptionFailed:
            return "❌ Decryption failed. The data may be corrupted or the key is incorrect."
        case .invalidData:
            return "❌ Invalid encrypted data format."
        }
    }
}

/// Helper for streaming AES-GCM encryption/decryption.
///
/// **Encryption Format:**
/// The stream is broken into chunks. Each chunk is encrypted independently.
///
/// Each Encrypted Chunk Structure:
/// ```
/// | Nonce (12 bytes) | Ciphertext (chunkSize bytes) | Tag (16 bytes) |
/// ```
///
/// The overhead per chunk is 28 bytes (12 nonce + 16 tag).
// MARK: - Generic Streaming Encryption

public struct StreamingEncryption {

    /// Default chunk size (1MB).
    public static let chunkSize = 1024 * 1024
    
    /// Minimum chunk size (256KB).
    public static let minChunkSize = 256 * 1024
    
    /// Maximum chunk size (16MB).
    public static let maxChunkSize = 16 * 1024 * 1024
    
    /// Encryption overhead per chunk (nonce + tag).
    public static let overhead = 28
    
    /// Calculates the optimal chunk size based on file size.
    ///
    /// - Parameter fileSize: The total file size in bytes.
    /// - Returns: The recommended chunk size.
    public static func optimalChunkSize(forFileSize fileSize: Int64) -> Int {
        switch fileSize {
        case ..<(10 * 1024 * 1024):           // < 10MB
            return minChunkSize                // 256KB chunks
        case ..<(100 * 1024 * 1024):          // < 100MB
            return chunkSize                   // 1MB chunks
        case ..<(1024 * 1024 * 1024):         // < 1GB
            return 5 * 1024 * 1024             // 5MB chunks
        default:                               // >= 1GB
            return maxChunkSize                // 16MB chunks
        }
    }
    
    /// Calculates the encrypted size for a given plaintext size.
    ///
    /// - Parameters:
    ///   - plaintextSize: The size of the plaintext data.
    ///   - chunkSize: The chunk size being used.
    /// - Returns: The total encrypted size including overhead.
    public static func encryptedSize(plaintextSize: Int64, chunkSize: Int = StreamingEncryption.chunkSize) -> Int64 {
        let fullChunks = plaintextSize / Int64(chunkSize)
        let remainder = plaintextSize % Int64(chunkSize)
        
        var totalSize = fullChunks * Int64(chunkSize + overhead)
        if remainder > 0 {
            totalSize += remainder + Int64(overhead)
        }
        return totalSize
    }
    
    // Wrapper for SymmetricKey to allow Sendable conformance
    struct SendableKey: @unchecked Sendable {
        let key: SymmetricKey
    }
    
    /// An AsyncSequence that encrypts an upstream stream of ByteBuffers in chunks.
    ///
    /// Each chunk yielded by the upstream sequence is encrypted as a separate AES-GCM block.
    public struct EncryptedStream<Upstream: AsyncSequence & Sendable>: AsyncSequence, Sendable where Upstream.Element == ByteBuffer {
        public typealias Element = Data
        
        let upstream: Upstream
        let keyWrapper: SendableKey
        
        var key: SymmetricKey { keyWrapper.key }
        
        public init(upstream: Upstream, key: SymmetricKey) {
            self.upstream = upstream
            self.keyWrapper = SendableKey(key: key)
        }
        
        public struct AsyncIterator: AsyncIteratorProtocol {
            var upstreamIterator: Upstream.AsyncIterator
            let key: SymmetricKey
            
            public mutating func next() async throws -> Data? {
                guard let chunk = try await upstreamIterator.next() else {
                    return nil
                }
                
                let data = Data(buffer: chunk)
                // Encrypt each chunk independently with a unique random nonce.
                // SealedBox.combined returns: Nonce + Ciphertext + Tag
                let sealedBox = try AES.GCM.seal(data, using: key)
                return sealedBox.combined
            }
        }
        
        public func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator(upstreamIterator: upstream.makeAsyncIterator(), key: key)
        }
    }
    
    /// An AsyncSequence that decrypts a stream of encrypted Data chunks.
    ///
    /// - Important: The upstream must yield chunks that align with the encrypted block boundaries.
    ///   Since S3 or HTTP clients might buffer data differently, this stream implements buffering logic
    ///   to ensure it always processes complete encrypted blocks (chunkSize + 28 bytes).
    public struct DecryptedStream<Upstream: AsyncSequence & Sendable>: AsyncSequence, Sendable where Upstream.Element == Data {
        public typealias Element = Data
        
        let upstream: Upstream
        let keyWrapper: SendableKey
        
        var key: SymmetricKey { keyWrapper.key }
        
        public init(upstream: Upstream, key: SymmetricKey) {
            self.upstream = upstream
            self.keyWrapper = SendableKey(key: key)
        }
        
        // Size of a full encrypted block including overhead
        let fullWebBlockSize = StreamingEncryption.chunkSize + 28
        
        public struct AsyncIterator: AsyncIteratorProtocol {
            var upstreamIterator: Upstream.AsyncIterator
            let key: SymmetricKey
            var buffer = Data()
            
            public mutating func next() async throws -> Data? {
                // We need to accumulate at least enough data for one block or end of stream
                
                while true {
                    // 1. If buffer has enough for a full block (standard size), process it
                    if buffer.count >= StreamingEncryption.chunkSize + 28 {
                        let blockSize = StreamingEncryption.chunkSize + 28
                        let blockData = buffer.prefix(blockSize)
                        buffer.removeFirst(blockSize)
                        
                        let sealedBox = try AES.GCM.SealedBox(combined: blockData)
                        return try AES.GCM.open(sealedBox, using: key)
                    }
                    
                    // 2. Fetch more data
                    guard let chunk = try await upstreamIterator.next() else {
                        // End of stream
                        if !buffer.isEmpty {
                            // Process remaining data (Last chunk)
                            // It must be a valid sealed box (size >= 28)
                            guard buffer.count >= 28 else {
                                throw StreamingEncryptionError.invalidData
                            }
                            
                            let sealedBox = try AES.GCM.SealedBox(combined: buffer)
                            let data = try AES.GCM.open(sealedBox, using: key)
                            buffer.removeAll()
                            return data
                        }
                        return nil
                    }
                    
                    buffer.append(chunk)
                }
            }
        }
        
        public func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator(upstreamIterator: upstream.makeAsyncIterator(), key: key)
        }
    }
}
