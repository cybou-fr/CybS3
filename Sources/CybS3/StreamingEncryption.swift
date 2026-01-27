import Foundation
import Crypto

enum StreamingEncryptionError: Error {
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
/// ```
///
/// - `chunkSize` is 1MB (1,048,576 bytes).
/// - Total overhead per chunk is 28 bytes.
/// - The total size of an encrypted part is `chunkSize + 28`.
/// - The last chunk may be smaller than `chunkSize`, but will still have 28 bytes overhead.
///
struct StreamingEncryption {

    static let chunkSize = 1024 * 1024 
    
    // Wrapper for SymmetricKey to allow Sendable conformance
    // SymmetricKey is a value type wrapping SecureBytes.
    /// A wrapper for `SymmetricKey` to allow Sendable conformance.
    /// `SymmetricKey` internally wraps `SecureBytes` but is not marked Sendable in all versions.
    struct SendableKey: @unchecked Sendable {
        let key: SymmetricKey
    }
    
    /// An AsyncSequence that encrypts an upstream file stream in chunks.
    ///
    /// Each chunk yielded by the upstream `FileHandleAsyncSequence` is encrypted as a separate AES-GCM block.
    /// This allows for streaming uploads where the total size might be large, but we only keep one chunk in memory.
    struct EncryptedStream: AsyncSequence, Sendable {
        typealias Element = Data
        
        let upstream: FileHandleAsyncSequence
        let keyWrapper: SendableKey
        
        var key: SymmetricKey { keyWrapper.key }
        
        init(upstream: FileHandleAsyncSequence, key: SymmetricKey) {
            self.upstream = upstream
            self.keyWrapper = SendableKey(key: key)
        }
        
        struct AsyncIterator: AsyncIteratorProtocol {
            var upstreamIterator: FileHandleAsyncSequence.AsyncIterator
            let key: SymmetricKey
            
            mutating func next() async throws -> Data? {
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
        
        func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator(upstreamIterator: upstream.makeAsyncIterator(), key: key)
        }
    }
    
    /// An AsyncSequence that decrypts a stream of encrypted Data chunks.
    ///
    /// - Important: The upstream must yield chunks that align with the encrypted block boundaries.
    ///   Since S3 or HTTP clients might buffer data differently, this stream implements buffering logic
    ///   to ensure it always processes complete encrypted blocks (chunkSize + 28 bytes).
    struct DecryptedStream: AsyncSequence, Sendable {
        typealias Element = Data
        
        let upstream: AsyncThrowingStream<Data, Error>
        let keyWrapper: SendableKey
        
        var key: SymmetricKey { keyWrapper.key }
        
        init(upstream: AsyncThrowingStream<Data, Error>, key: SymmetricKey) {
            self.upstream = upstream
            self.keyWrapper = SendableKey(key: key)
        }
        
        // Size of a full encrypted block including overhead
        let fullWebBlockSize = StreamingEncryption.chunkSize + 28
        
        struct AsyncIterator: AsyncIteratorProtocol {
            var upstreamIterator: AsyncThrowingStream<Data, Error>.Iterator
            let key: SymmetricKey
            var buffer = Data()
            
            mutating func next() async throws -> Data? {
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
        
        func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator(upstreamIterator: upstream.makeAsyncIterator(), key: key)
        }
    }
}
