import Foundation

/// Platform-specific optimizations and utilities.
public struct PlatformSpecific {
    /// Optimal thread count for concurrent operations.
    public static var optimalThreadCount: Int {
        #if os(macOS)
        return min(ProcessInfo.processInfo.activeProcessorCount, 16)
        #elseif os(Windows)
        return min(System.coreCount, 16)
        #else
        return System.coreCount
        #endif
    }
    
    /// Optimal buffer size for I/O operations.
    public static var optimalBufferSize: Int {
        #if os(macOS) || os(iOS)
        return 64 * 1024 // 64KB for Apple platforms
        #else
        return 128 * 1024 // 128KB for others
        #endif
    }
    
    /// Whether the platform supports secure memory operations.
    public static var supportsSecureMemory: Bool {
        #if os(macOS) || os(Linux)
        return true
        #else
        return false
        #endif
    }
    
    /// Get system memory information.
    public static var systemMemoryGB: Double {
        #if os(macOS)
        let processInfo = ProcessInfo.processInfo
        return Double(processInfo.physicalMemory) / (1024 * 1024 * 1024)
        #else
        // Estimate based on core count for other platforms
        return Double(System.coreCount) * 2.0 // Rough estimate
        #endif
    }
    
    /// Recommended chunk size for large file operations based on available memory.
    public static var recommendedChunkSize: Int {
        let memoryGB = systemMemoryGB
        if memoryGB > 16 {
            return 16 * 1024 * 1024 // 16MB for high-memory systems
        } else if memoryGB > 8 {
            return 8 * 1024 * 1024 // 8MB for medium-memory systems
        } else {
            return 4 * 1024 * 1024 // 4MB for low-memory systems
        }
    }
    
    /// Platform-specific temporary directory.
    public static var temporaryDirectory: URL {
        #if os(macOS) || os(iOS)
        return FileManager.default.temporaryDirectory
        #else
        // Use /tmp on Linux/Windows
        return URL(fileURLWithPath: "/tmp")
        #endif
    }
    
    /// Check if running in a containerized environment.
    public static var isContainerized: Bool {
        #if os(Linux)
        return FileManager.default.fileExists(atPath: "/.dockerenv") ||
               FileManager.default.fileExists(atPath: "/run/.containerenv")
        #else
        return false
        #endif
    }
    
    /// Get platform-specific user agent string.
    public static var userAgent: String {
        let version = "1.0.0" // Would be set by build system
        #if os(macOS)
        return "CybS3/\(version) (macOS)"
        #elseif os(Linux)
        return "CybS3/\(version) (Linux)"
        #elseif os(Windows)
        return "CybS3/\(version) (Windows)"
        #else
        return "CybS3/\(version) (Unknown)"
        #endif
    }
}