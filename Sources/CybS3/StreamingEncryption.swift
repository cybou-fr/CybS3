import Foundation
import Crypto

enum StreamingEncryptionError: Error {
    case encryptionFailed
    case decryptionFailed
    case invalidData
}

struct StreamingEncryption {

    static let chunkSize = 1024 * 1024 
    
    // Wrapper for SymmetricKey to allow Sendable conformance
    // SymmetricKey is a value type wrapping SecureBytes, generally thread-safe for reading.
    struct SendableKey: @unchecked Sendable {
        let key: SymmetricKey
    }
    
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
                // Encrypt each chunk independently
                // In a real stream protocol we might want to chain them or use a counter nonce,
                // but independent chunks with random nonces is also valid for file storage if overhead is acceptable.
                // Overhead is: 12 bytes (nonce) + 16 bytes (tag) = 28 bytes per 1MB. Negligible.
                
                let sealedBox = try AES.GCM.seal(data, using: key)
                return sealedBox.combined // Returns nonce + ciphertext + tag
            }
        }
        
        func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator(upstreamIterator: upstream.makeAsyncIterator(), key: key)
        }
    }
    
    // Decrypts a stream of Data (chunks)
    // IMPORTANT: The upstream must yield chunks that exactly match the encrypted block boundaries.
    // If S3 or HTTP client alters chunk sizes, this naive implementations will fail.
    // For S3 "Get", we typically get a byte stream. We need to re-assemble the encrypted blocks.
    // Encrypted Block Size = 1MB + 12 (nonce) + 16 (tag) = 1048604 bytes.
    // Except the last block which is smaller.
    
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
                    // If buffer has enough for a full block, process it
                    if buffer.count >= StreamingEncryption.chunkSize + 28 {
                        let blockSize = StreamingEncryption.chunkSize + 28
                        let blockData = buffer.prefix(blockSize)
                        buffer.removeFirst(blockSize)
                        
                        let sealedBox = try AES.GCM.SealedBox(combined: blockData)
                        return try AES.GCM.open(sealedBox, using: key)
                    }
                    
                    // Fetch more data
                    guard let chunk = try await upstreamIterator.next() else {
                        // End of stream
                        if !buffer.isEmpty {
                            // Process remaining data
                            // It must be a valid sealed box
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
