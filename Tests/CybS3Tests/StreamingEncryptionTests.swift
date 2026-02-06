import XCTest
@preconcurrency import Crypto
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
                
                let end = Swift.min(offset + chunkSize, data.count)
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
    
    // MARK: - Edge Case Tests
    
    func testEmptyDataEncryption() async throws {
        // Test encrypting empty data
        let originalData = Data()
        let key = SymmetricKey(size: .bits256)
        
        let mockStream = MockStream(data: originalData, chunkSize: StreamingEncryption.chunkSize)
        let encryptedStream = StreamingEncryption.EncryptedStream(upstream: mockStream, key: key)
        
        var encryptedChunks: [Data] = []
        for try await chunk in encryptedStream {
            encryptedChunks.append(chunk)
        }
        
        // Empty input should produce no output chunks
        XCTAssertTrue(encryptedChunks.isEmpty)
    }
    
    func testExactlyOneChunk() async throws {
        // Test data that is exactly 1 chunk size
        let originalData = Data(repeating: 0xAB, count: StreamingEncryption.chunkSize)
        let key = SymmetricKey(size: .bits256)
        
        let mockStream = MockStream(data: originalData, chunkSize: StreamingEncryption.chunkSize)
        let encryptedStream = StreamingEncryption.EncryptedStream(upstream: mockStream, key: key)
        
        var encryptedChunks: [Data] = []
        for try await chunk in encryptedStream {
            encryptedChunks.append(chunk)
        }
        
        // Should produce exactly 1 encrypted chunk
        XCTAssertEqual(encryptedChunks.count, 1)
        XCTAssertEqual(encryptedChunks[0].count, StreamingEncryption.chunkSize + StreamingEncryption.overhead)
        
        // Decrypt and verify
        let mockEncryptedStream = MockDataStream(chunks: encryptedChunks)
        let decryptedStream = StreamingEncryption.DecryptedStream(upstream: mockEncryptedStream, key: key)
        
        var decryptedData = Data()
        for try await chunk in decryptedStream {
            decryptedData.append(chunk)
        }
        
        XCTAssertEqual(decryptedData, originalData)
    }
    
    func testOneChunkPlusOneByte() async throws {
        // Test data that is exactly 1 chunk + 1 byte
        let originalData = Data(repeating: 0xCD, count: StreamingEncryption.chunkSize + 1)
        let key = SymmetricKey(size: .bits256)
        
        let mockStream = MockStream(data: originalData, chunkSize: StreamingEncryption.chunkSize)
        let encryptedStream = StreamingEncryption.EncryptedStream(upstream: mockStream, key: key)
        
        var encryptedChunks: [Data] = []
        for try await chunk in encryptedStream {
            encryptedChunks.append(chunk)
        }
        
        // Should produce 2 encrypted chunks
        XCTAssertEqual(encryptedChunks.count, 2)
        
        // First chunk: full size
        XCTAssertEqual(encryptedChunks[0].count, StreamingEncryption.chunkSize + StreamingEncryption.overhead)
        
        // Second chunk: 1 byte + overhead
        XCTAssertEqual(encryptedChunks[1].count, 1 + StreamingEncryption.overhead)
        
        // Decrypt and verify
        let mockEncryptedStream = MockDataStream(chunks: encryptedChunks)
        let decryptedStream = StreamingEncryption.DecryptedStream(upstream: mockEncryptedStream, key: key)
        
        var decryptedData = Data()
        for try await chunk in decryptedStream {
            decryptedData.append(chunk)
        }
        
        XCTAssertEqual(decryptedData, originalData)
    }
    
    func testDecryptionWithWrongKeyFails() async throws {
        let originalData = "Secret message".data(using: .utf8)!
        let correctKey = SymmetricKey(size: .bits256)
        let wrongKey = SymmetricKey(size: .bits256)
        
        // Encrypt with correct key
        let mockStream = MockStream(data: originalData, chunkSize: StreamingEncryption.chunkSize)
        let encryptedStream = StreamingEncryption.EncryptedStream(upstream: mockStream, key: correctKey)
        
        var encryptedChunks: [Data] = []
        for try await chunk in encryptedStream {
            encryptedChunks.append(chunk)
        }
        
        // Try to decrypt with wrong key - should fail
        let mockEncryptedStream = MockDataStream(chunks: encryptedChunks)
        let decryptedStream = StreamingEncryption.DecryptedStream(upstream: mockEncryptedStream, key: wrongKey)
        
        do {
            for try await _ in decryptedStream {
                XCTFail("Decryption with wrong key should have failed")
            }
        } catch {
            // Expected - decryption should fail with wrong key
            XCTAssertTrue(true)
        }
    }
    
    func testEncryptedSizeCalculation() {
        // Test the encrypted size calculation helper
        
        // Empty file
        XCTAssertEqual(StreamingEncryption.encryptedSize(plaintextSize: 0), 0)
        
        // 1 byte file
        XCTAssertEqual(StreamingEncryption.encryptedSize(plaintextSize: 1), 1 + Int64(StreamingEncryption.overhead))
        
        // Exactly 1 chunk
        let chunkSize = Int64(StreamingEncryption.chunkSize)
        XCTAssertEqual(
            StreamingEncryption.encryptedSize(plaintextSize: chunkSize),
            chunkSize + Int64(StreamingEncryption.overhead)
        )
        
        // 1 chunk + 1 byte
        XCTAssertEqual(
            StreamingEncryption.encryptedSize(plaintextSize: chunkSize + 1),
            chunkSize + Int64(StreamingEncryption.overhead) + 1 + Int64(StreamingEncryption.overhead)
        )
        
        // 5 chunks
        XCTAssertEqual(
            StreamingEncryption.encryptedSize(plaintextSize: 5 * chunkSize),
            5 * (chunkSize + Int64(StreamingEncryption.overhead))
        )
    }
    
    func testOptimalChunkSize() {
        // Test the adaptive chunk size helper
        
        // Small file (< 10MB) should use min chunk size
        XCTAssertEqual(
            StreamingEncryption.optimalChunkSize(forFileSize: 5 * 1024 * 1024),
            StreamingEncryption.minChunkSize
        )
        
        // Medium file (< 100MB) should use default chunk size
        XCTAssertEqual(
            StreamingEncryption.optimalChunkSize(forFileSize: 50 * 1024 * 1024),
            StreamingEncryption.chunkSize
        )
        
        // Large file (>= 1GB) should use max chunk size
        XCTAssertEqual(
            StreamingEncryption.optimalChunkSize(forFileSize: 2 * 1024 * 1024 * 1024),
            StreamingEncryption.maxChunkSize
        )
    }
    
    // MARK: - Additional Edge Case Tests
    
    func testVerySmallData() async throws {
        // Test with just a few bytes
        let originalData = Data([0x01, 0x02, 0x03])
        let key = SymmetricKey(size: .bits256)
        
        let mockStream = MockStream(data: originalData, chunkSize: StreamingEncryption.chunkSize)
        let encryptedStream = StreamingEncryption.EncryptedStream(upstream: mockStream, key: key)
        
        var encryptedChunks: [Data] = []
        for try await chunk in encryptedStream {
            encryptedChunks.append(chunk)
        }
        
        XCTAssertEqual(encryptedChunks.count, 1)
        XCTAssertEqual(encryptedChunks[0].count, 3 + StreamingEncryption.overhead)
        
        // Decrypt and verify
        let mockEncryptedStream = MockDataStream(chunks: encryptedChunks)
        let decryptedStream = StreamingEncryption.DecryptedStream(upstream: mockEncryptedStream, key: key)
        
        var decryptedData = Data()
        for try await chunk in decryptedStream {
            decryptedData.append(chunk)
        }
        
        XCTAssertEqual(decryptedData, originalData)
    }
    
    func testSingleByteEncryption() async throws {
        let originalData = Data([0xFF])
        let key = SymmetricKey(size: .bits256)
        
        let mockStream = MockStream(data: originalData, chunkSize: StreamingEncryption.chunkSize)
        let encryptedStream = StreamingEncryption.EncryptedStream(upstream: mockStream, key: key)
        
        var encryptedChunks: [Data] = []
        for try await chunk in encryptedStream {
            encryptedChunks.append(chunk)
        }
        
        XCTAssertEqual(encryptedChunks.count, 1)
        
        // Decrypt
        let mockEncryptedStream = MockDataStream(chunks: encryptedChunks)
        let decryptedStream = StreamingEncryption.DecryptedStream(upstream: mockEncryptedStream, key: key)
        
        var decryptedData = Data()
        for try await chunk in decryptedStream {
            decryptedData.append(chunk)
        }
        
        XCTAssertEqual(decryptedData, originalData)
        XCTAssertEqual(decryptedData.count, 1)
        XCTAssertEqual(decryptedData[0], 0xFF)
    }
    
    func testMultipleChunksExactBoundary() async throws {
        // Test data that is exactly N chunks (no remainder)
        let numChunks = 3
        let originalData = Data(repeating: 0x42, count: numChunks * StreamingEncryption.chunkSize)
        let key = SymmetricKey(size: .bits256)
        
        let mockStream = MockStream(data: originalData, chunkSize: StreamingEncryption.chunkSize)
        let encryptedStream = StreamingEncryption.EncryptedStream(upstream: mockStream, key: key)
        
        var encryptedChunks: [Data] = []
        for try await chunk in encryptedStream {
            encryptedChunks.append(chunk)
        }
        
        XCTAssertEqual(encryptedChunks.count, numChunks)
        
        // All chunks should be full size
        for chunk in encryptedChunks {
            XCTAssertEqual(chunk.count, StreamingEncryption.chunkSize + StreamingEncryption.overhead)
        }
        
        // Decrypt and verify
        let mockEncryptedStream = MockDataStream(chunks: encryptedChunks)
        let decryptedStream = StreamingEncryption.DecryptedStream(upstream: mockEncryptedStream, key: key)
        
        var decryptedData = Data()
        for try await chunk in decryptedStream {
            decryptedData.append(chunk)
        }
        
        XCTAssertEqual(decryptedData, originalData)
    }
    
    func testEncryptedSizeCalculationEdgeCases() {
        let chunkSize = Int64(StreamingEncryption.chunkSize)
        let overhead = Int64(StreamingEncryption.overhead)
        
        // Test with custom chunk sizes
        XCTAssertEqual(
            StreamingEncryption.encryptedSize(plaintextSize: 0, chunkSize: 256 * 1024),
            0
        )
        
        XCTAssertEqual(
            StreamingEncryption.encryptedSize(plaintextSize: 100, chunkSize: 256 * 1024),
            100 + overhead
        )
        
        // 2 chunks + partial
        let twoAndHalf = chunkSize * 2 + chunkSize / 2
        let expected = 2 * (chunkSize + overhead) + (chunkSize / 2) + overhead
        XCTAssertEqual(
            StreamingEncryption.encryptedSize(plaintextSize: twoAndHalf),
            expected
        )
    }
    
    func testOptimalChunkSizeBoundaries() {
        // Test exact boundaries
        
        // Exactly 10MB - should transition from min to default
        let tenMB: Int64 = 10 * 1024 * 1024
        XCTAssertEqual(
            StreamingEncryption.optimalChunkSize(forFileSize: tenMB - 1),
            StreamingEncryption.minChunkSize
        )
        XCTAssertEqual(
            StreamingEncryption.optimalChunkSize(forFileSize: tenMB),
            StreamingEncryption.chunkSize
        )
        
        // Exactly 100MB - should transition from default to 5MB chunks
        let hundredMB: Int64 = 100 * 1024 * 1024
        XCTAssertEqual(
            StreamingEncryption.optimalChunkSize(forFileSize: hundredMB - 1),
            StreamingEncryption.chunkSize
        )
        XCTAssertEqual(
            StreamingEncryption.optimalChunkSize(forFileSize: hundredMB),
            5 * 1024 * 1024
        )
        
        // Exactly 1GB - should transition to max chunk size
        let oneGB: Int64 = 1024 * 1024 * 1024
        XCTAssertEqual(
            StreamingEncryption.optimalChunkSize(forFileSize: oneGB - 1),
            5 * 1024 * 1024
        )
        XCTAssertEqual(
            StreamingEncryption.optimalChunkSize(forFileSize: oneGB),
            StreamingEncryption.maxChunkSize
        )
        
        // Very small files
        XCTAssertEqual(
            StreamingEncryption.optimalChunkSize(forFileSize: 0),
            StreamingEncryption.minChunkSize
        )
        XCTAssertEqual(
            StreamingEncryption.optimalChunkSize(forFileSize: 1),
            StreamingEncryption.minChunkSize
        )
    }
    
    func testStreamConstantValues() {
        // Verify constant values are as expected
        XCTAssertEqual(StreamingEncryption.chunkSize, 1024 * 1024) // 1MB
        XCTAssertEqual(StreamingEncryption.minChunkSize, 256 * 1024) // 256KB
        XCTAssertEqual(StreamingEncryption.maxChunkSize, 16 * 1024 * 1024) // 16MB
        XCTAssertEqual(StreamingEncryption.overhead, 28) // 12 nonce + 16 tag
    }
    
    func testDecryptionWithInvalidDataTooShort() async throws {
        let key = SymmetricKey(size: .bits256)
        
        // Create data that is too short to be valid (less than 28 bytes overhead)
        let invalidData = Data(repeating: 0x00, count: 10)
        let mockEncryptedStream = MockDataStream(chunks: [invalidData])
        let decryptedStream = StreamingEncryption.DecryptedStream(upstream: mockEncryptedStream, key: key)
        
        do {
            for try await _ in decryptedStream {
                XCTFail("Should have thrown an error for invalid data")
            }
        } catch {
            // Expected - should throw invalidData or decryption error
            XCTAssertTrue(true)
        }
    }
    
    func testEncryptionPreservesDataIntegrity() async throws {
        // Test with binary data containing all byte values
        var originalData = Data()
        for byte: UInt8 in 0...255 {
            originalData.append(byte)
        }
        // Repeat to make it larger
        originalData.append(originalData)
        originalData.append(originalData)
        
        let key = SymmetricKey(size: .bits256)
        
        let mockStream = MockStream(data: originalData, chunkSize: StreamingEncryption.chunkSize)
        let encryptedStream = StreamingEncryption.EncryptedStream(upstream: mockStream, key: key)
        
        var encryptedChunks: [Data] = []
        for try await chunk in encryptedStream {
            encryptedChunks.append(chunk)
        }
        
        // Decrypt
        let mockEncryptedStream = MockDataStream(chunks: encryptedChunks)
        let decryptedStream = StreamingEncryption.DecryptedStream(upstream: mockEncryptedStream, key: key)
        
        var decryptedData = Data()
        for try await chunk in decryptedStream {
            decryptedData.append(chunk)
        }
        
        XCTAssertEqual(decryptedData, originalData)
    }
    
    func testConcurrentEncryptions() async throws {
        // Test that multiple encryptions can run without interference
        let key1 = SymmetricKey(size: .bits256)
        let key2 = SymmetricKey(size: .bits256)
        let testData1 = Data(repeating: 0xAA, count: 1024)
        let testData2 = Data(repeating: 0xBB, count: 2048)
        
        async let result1: [Data] = {
            let stream = MockStream(data: testData1, chunkSize: StreamingEncryption.chunkSize)
            let encrypted = StreamingEncryption.EncryptedStream(upstream: stream, key: key1)
            var chunks: [Data] = []
            for try await chunk in encrypted {
                chunks.append(chunk)
            }
            return chunks
        }()
        
        async let result2: [Data] = {
            let stream = MockStream(data: testData2, chunkSize: StreamingEncryption.chunkSize)
            let encrypted = StreamingEncryption.EncryptedStream(upstream: stream, key: key2)
            var chunks: [Data] = []
            for try await chunk in encrypted {
                chunks.append(chunk)
            }
            return chunks
        }()
        
        let (chunks1, chunks2) = try await (result1, result2)
        
        // Decrypt both
        let decrypted1 = try await decryptChunks(chunks1, key: key1)
        let decrypted2 = try await decryptChunks(chunks2, key: key2)
        
        XCTAssertEqual(decrypted1, testData1)
        XCTAssertEqual(decrypted2, testData2)
    }
    
    private func decryptChunks(_ chunks: [Data], key: SymmetricKey) async throws -> Data {
        let stream = MockDataStream(chunks: chunks)
        let decrypted = StreamingEncryption.DecryptedStream(upstream: stream, key: key)
        var data = Data()
        for try await chunk in decrypted {
            data.append(chunk)
        }
        return data
    }
}
