import Foundation
import Crypto
import NIO

public enum StreamingEncryptionError: Error {
    case encryptionFailed
    case decryptionFailed
    case invalidData
}

/// Helper for streaming AES-GCM encryption/decryption.
///
/// **Encryption Format:**
/// The stream is broken into chunks. Each chunk is encrypted independently.
///
/// Each Encrypted Chunk Structure:
/// ```
/// | Nonce (12 bytes) | Ciphertext (chunkSize bytes) | Tag (16 bytes) |
// MARK: - Generic Streaming Encryption

public struct StreamingEncryption {

    public static let chunkSize = 1024 * 1024 
    
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
