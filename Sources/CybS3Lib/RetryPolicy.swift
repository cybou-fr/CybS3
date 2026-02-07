import Foundation

/// Defines retry behavior for operations that may fail transiently.
public struct RetryPolicy: Sendable {
    /// Maximum number of retry attempts.
    public let maxAttempts: Int
    /// Base delay between retries in seconds.
    public let baseDelay: TimeInterval
    /// Maximum delay between retries in seconds.
    public let maxDelay: TimeInterval
    /// Jitter factor to randomize delays (0.0 to 1.0).
    public let jitterFactor: Double
    
    /// Creates a new retry policy.
    ///
    /// - Parameters:
    ///   - maxAttempts: Maximum number of retry attempts (including initial attempt).
    ///   - baseDelay: Base delay in seconds for exponential backoff.
    ///   - maxDelay: Maximum delay in seconds.
    ///   - jitterFactor: Randomization factor (0.0 = no jitter, 1.0 = full randomization).
    public init(
        maxAttempts: Int = 3,
        baseDelay: TimeInterval = 1.0,
        maxDelay: TimeInterval = 30.0,
        jitterFactor: Double = 0.1
    ) {
        self.maxAttempts = maxAttempts
        self.baseDelay = baseDelay
        self.maxDelay = maxDelay
        self.jitterFactor = jitterFactor
    }
    
    /// Calculates the delay for a given attempt number.
    ///
    /// - Parameter attempt: The attempt number (0-based).
    /// - Returns: The delay in seconds before the next attempt.
    public func delay(for attempt: Int) -> TimeInterval {
        let exponentialDelay = baseDelay * pow(2.0, Double(attempt))
        let jitter = Double.random(in: 0...jitterFactor) * exponentialDelay
        return min(exponentialDelay + jitter, maxDelay)
    }
    
    /// Executes an operation with retry logic.
    ///
    /// - Parameters:
    ///   - operation: The async operation to retry.
    ///   - shouldRetry: Optional predicate to determine if an error should be retried.
    /// - Returns: The result of the successful operation.
    /// - Throws: The last error if all retries are exhausted.
    public func execute<T>(
        _ operation: () async throws -> T,
        shouldRetry: ((Error) -> Bool)? = nil
    ) async throws -> T {
        var lastError: Error?
        
        for attempt in 0..<maxAttempts {
            do {
                return try await operation()
            } catch {
                lastError = error
                
                // Check if we should retry this error
                let shouldRetryError = shouldRetry?(error) ?? defaultShouldRetry(error)
                
                if attempt < maxAttempts - 1 && shouldRetryError {
                    let delay = self.delay(for: attempt)
                    try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                } else {
                    break
                }
            }
        }
        
        throw lastError!
    }
    
    /// Default predicate for determining if an error should be retried.
    private func defaultShouldRetry(_ error: Error) -> Bool {
        // Retry network errors, timeouts, and certain S3 errors
        if let s3Error = error as? S3Error {
            switch s3Error {
            case .requestFailed(let status, _, _):
                // Retry 5xx errors and some 4xx errors
                return status >= 500 || status == 429 || status == 408
            default:
                return false
            }
        }
        
        // Retry URLError network errors
        if error is URLError {
            return true
        }
        
        return false
    }
    
    /// Predefined retry policies for common scenarios.
    public enum Policy {
        /// Fast retries for quick operations.
        public static let fast = RetryPolicy(maxAttempts: 3, baseDelay: 0.5, maxDelay: 5.0)
        
        /// Standard retries for normal operations.
        public static let standard = RetryPolicy(maxAttempts: 3, baseDelay: 1.0, maxDelay: 30.0)
        
        /// Slow retries for long-running operations.
        public static let slow = RetryPolicy(maxAttempts: 5, baseDelay: 2.0, maxDelay: 120.0)
        
        /// Aggressive retries for critical operations.
        public static let aggressive = RetryPolicy(maxAttempts: 5, baseDelay: 1.0, maxDelay: 60.0)
    }
}