import Foundation
import NIOCore
import NIOFoundationCompat

func createTestData(size: Int) -> Data {
    var data = Data(capacity: size)
    for i in 0..<size {
        data.append(UInt8(i % 256))
    }
    return data
}

func createRandomData(size: Int) -> Data {
    var data = Data(capacity: size)
    for _ in 0..<size {
        data.append(UInt8.random(in: 0...255))
    }
    return data
}

func createLargeData(size: Int) -> Data {
    return createTestData(size: size)
}

func createStream(from data: Data, chunkSize: Int = 1024 * 1024) -> AsyncStream<ByteBuffer> {
    return AsyncStream<ByteBuffer> { continuation in
        var offset = 0
        while offset < data.count {
            let end = min(offset + chunkSize, data.count)
            let chunk = data[offset..<end]
            continuation.yield(ByteBuffer(data: Data(chunk)))
            offset = end
        }
        continuation.finish()
    }
}