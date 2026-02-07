import Foundation

/// Cross-platform lock implementation that uses the most efficient locking mechanism available on each platform.
public final class CrossPlatformLock: @unchecked Sendable {
    #if os(macOS)
    private var unfairLock = os_unfair_lock()
    #else
    private var mutex = pthread_mutex_t()
    
    init() {
        let result = pthread_mutex_init(&mutex, nil)
        precondition(result == 0, "Failed to initialize mutex")
    }
    
    deinit {
        pthread_mutex_destroy(&mutex)
    }
    #endif
    
    /// Acquire the lock.
    public func lock() {
        #if os(macOS)
        os_unfair_lock_lock(&unfairLock)
        #else
        pthread_mutex_lock(&mutex)
        #endif
    }
    
    /// Release the lock.
    public func unlock() {
        #if os(macOS)
        os_unfair_lock_unlock(&unfairLock)
        #else
        pthread_mutex_unlock(&mutex)
        #endif
    }
    
    /// Execute a closure while holding the lock.
    public func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
    
    /// Execute an async closure while holding the lock.
    public func withLock<T>(_ body: () async throws -> T) async rethrows -> T {
        lock()
        defer { unlock() }
        return try await body()
    }
}