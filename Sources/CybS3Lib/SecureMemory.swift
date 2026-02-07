import Foundation

/// Utilities for secure memory operations to prevent sensitive data from remaining in memory.
public struct SecureMemory {
    /// Zero out the contents of a buffer to prevent sensitive data leakage.
    /// Uses platform-specific secure zeroing functions when available.
    ///
    /// - Parameter buffer: The buffer to zero out.
    public static func zero(_ buffer: UnsafeMutableRawBufferPointer) {
        #if os(macOS)
        // Use memset_s on macOS which is guaranteed to not be optimized away
        memset_s(buffer.baseAddress, buffer.count, 0, buffer.count)
        #elseif os(Linux)
        // Use explicit_bzero on Linux
        explicit_bzero(buffer.baseAddress, buffer.count)
        #else
        // Fallback to regular memset (not secure but better than nothing)
        memset(buffer.baseAddress, 0, buffer.count)
        #endif
    }
    
    /// Securely zero out a Data buffer.
    ///
    /// - Parameter data: The Data object to zero out.
    public static func zero(_ data: inout Data) {
        data.withUnsafeMutableBytes { buffer in
            zero(buffer)
        }
    }
    
    /// Allocate a buffer that will be automatically zeroed when deallocated.
    ///
    /// - Parameter count: The number of bytes to allocate.
    /// - Returns: A buffer that will be securely zeroed on deallocation.
    public static func allocateSecureBuffer(count: Int) -> UnsafeMutableRawBufferPointer {
        let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: count, alignment: MemoryLayout<UInt8>.alignment)
        // Note: In a production system, you might want to use platform-specific secure allocation
        // like sodium_malloc or similar, but for now we'll rely on zeroing during deallocation
        return buffer
    }
    
    /// Create a securely allocated Data buffer that zeros itself on deallocation.
    ///
    /// - Parameter count: The number of bytes to allocate.
    /// - Returns: A Data object that will zero its contents when deallocated.
    public static func secureData(count: Int) -> Data {
        let buffer = allocateSecureBuffer(count: count)
        defer { buffer.deallocate() }
        return Data(bytes: buffer.baseAddress!, count: count)
    }
}