import XCTest
import Crypto
import NIO
@testable import CybS3Lib

final class StreamingEncryptionTests: XCTestCase {
    
    // Mock AsyncSequence for ByteBuffers
    struct MockStream: AsyncSequence, Sendable {
        typealias Element = ByteBuffer
        
        let data: Data
        let chunkSize: Int
        
        struct AsyncIterator: AsyncIteratorProtocol {
            let data: Data
            let chunkSize: Int
            var offset = 0
            
            mutating func next() async throws -> ByteBuffer? {
                guard offset < data.count else { return nil }
                
                let end = min(offset + chunkSize, data.count)
                let chunkData = data[offset..<end]
                offset = end
                
                return ByteBuffer(data: Data(chunkData))
            }
        }
        
        func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator(data: data, chunkSize: chunkSize)
        }
    }
    
    // Mock AsyncSequence for Data (Encrypted)
    struct MockDataStream: AsyncSequence, Sendable {
        typealias Element = Data
        
        let chunks: [Data]
        
        struct AsyncIterator: AsyncIteratorProtocol {
            var iterator: IndexingIterator<[Data]>
            
            mutating func next() async throws -> Data? {
                return iterator.next()
            }
        }
        
        func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator(iterator: chunks.makeIterator())
        }
    }
    
    func testStreamingEncryptionDecryptionRoundTrip() async throws {
        // 1. Setup Data
        let originalString = String(repeating: "A", count: 5 * 1024 * 1024) // 5MB
        let originalData = originalString.data(using: .utf8)!
        
        let key = SymmetricKey(size: .bits256)
        
        // 2. Encryption
        // Use a smaller chunk size for testing if we could validly configure it, 
        // but StreamingEncryption.chunkSize is static let. 
        // We will respect the 1MB chunk size.
        let mockStream = MockStream(data: originalData, chunkSize: StreamingEncryption.chunkSize) // 1MB chunks
        
        let encryptedStream = StreamingEncryption.EncryptedStream(upstream: mockStream, key: key)
        
        var encryptedChunks: [Data] = []
        for try await chunk in encryptedStream {
            encryptedChunks.append(chunk)
            
            // Each chunk should be chunkSize + 28 bytes (except potentially the last one)
            // But here we feed exact multiples, so intermediate chunks should be full size.
        }
        
        XCTAssertFalse(encryptedChunks.isEmpty)
        
        // 3. Decryption
        let mockEncryptedStream = MockDataStream(chunks: encryptedChunks)
        let decryptedStream = StreamingEncryption.DecryptedStream(upstream: mockEncryptedStream, key: key)
        
        var decryptedData = Data()
        for try await chunk in decryptedStream {
            decryptedData.append(chunk)
        }
        
        // 4. Verify
        XCTAssertEqual(decryptedData, originalData)
        XCTAssertEqual(String(data: decryptedData, encoding: .utf8), originalString)
    }
    
    func testDecryptionWithPartialChunks() async throws {
        // Simulate network fragmentation where chunks arrive in random sizes
        
        let originalData = "Small data test for fragmentation logic.".data(using: .utf8)!
        let key = SymmetricKey(size: .bits256)
        
        // Encrypt first (single chunk)
        let mockStream = MockStream(data: originalData, chunkSize: 1024)
        let encryptedStream = StreamingEncryption.EncryptedStream(upstream: mockStream, key: key)
        
        var fullEncryptedData = Data()
        for try await chunk in encryptedStream {
            fullEncryptedData.append(chunk)
        }
        
        // Split encrypted data into tiny pieces (1 byte each) to test buffer logic
        var fragmentedChunks: [Data] = []
        for byte in fullEncryptedData {
            fragmentedChunks.append(Data([byte]))
        }
        
        let fragmentedStream = MockDataStream(chunks: fragmentedChunks)
        let decryptedStream = StreamingEncryption.DecryptedStream(upstream: fragmentedStream, key: key)
        
        var decryptedData = Data()
        for try await chunk in decryptedStream {
            decryptedData.append(chunk)
        }
        
        XCTAssertEqual(decryptedData, originalData)
    }
}
