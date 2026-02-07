import Foundation

/// Circuit breaker error types.
public enum CircuitBreakerError: Error, LocalizedError {
    case open
    
    public var errorDescription: String? {
        switch self {
        case .open:
            return "Circuit breaker is open - service temporarily unavailable"
        }
    }
}

/// Circuit breaker implementation for fault tolerance.
public actor CircuitBreaker {
    /// The current state of the circuit breaker.
    public enum State: Sendable {
        case closed
        case open
        case halfOpen
    }
    
    /// Current state of the circuit breaker.
    private var _state: State = .closed
    
    public var state: State {
        get async { _state }
    }
    
    /// Number of consecutive failures.
    private var failureCount = 0
    
    /// Timestamp when the circuit was opened.
    private var openedAt: Date?
    
    /// Configuration parameters.
    private let threshold: Int
    private let timeout: TimeInterval
    private let monitoringPeriod: TimeInterval
    
    /// Creates a new circuit breaker.
    ///
    /// - Parameters:
    ///   - threshold: Number of failures before opening the circuit.
    ///   - timeout: Time in seconds to wait before attempting half-open.
    ///   - monitoringPeriod: Time window in seconds for monitoring failures.
    public init(
        threshold: Int = 5,
        timeout: TimeInterval = 60.0,
        monitoringPeriod: TimeInterval = 60.0
    ) {
        self.threshold = threshold
        self.timeout = timeout
        self.monitoringPeriod = monitoringPeriod
    }
    
    /// Executes an operation through the circuit breaker.
    ///
    /// - Parameter operation: The async operation to execute.
    /// - Returns: The result of the operation.
    /// - Throws: CircuitBreakerError if circuit is open, or the operation's error.
    public func execute<T>(_ operation: () async throws -> T) async throws -> T {
        switch await state {
        case .open:
            if shouldAttemptReset() {
                _state = .halfOpen
            } else {
                throw CircuitBreakerError.open
            }
        case .closed, .halfOpen:
            break
        }
        
        do {
            let result = try await operation()
            onSuccess()
            return result
        } catch {
            onFailure()
            throw error
        }
    }
    
    /// Records a successful operation.
    private func onSuccess() {
        failureCount = 0
        if _state == .halfOpen {
            _state = .closed
        }
    }
    
    /// Records a failed operation.
    private func onFailure() {
        failureCount += 1
        if failureCount >= threshold {
            _state = .open
            openedAt = Date()
        }
    }
    
    /// Determines if the circuit should attempt to reset from open to half-open.
    private func shouldAttemptReset() -> Bool {
        guard let openedAt = openedAt else { return true }
        return Date().timeIntervalSince(openedAt) >= timeout
    }
    
    /// Gets the current failure count.
    public var currentFailureCount: Int {
        get async { failureCount }
    }
    
    /// Gets the time remaining until the circuit can be reset.
    public var timeUntilReset: TimeInterval? {
        guard let openedAt = openedAt, _state == .open else { return nil }
        let elapsed = Date().timeIntervalSince(openedAt)
        return max(0, timeout - elapsed)
    }
    
    /// Manually resets the circuit breaker to closed state.
    public func reset() {
        _state = .closed
        failureCount = 0
        openedAt = nil
    }
    
    /// Manually opens the circuit breaker.
    public func open() {
        _state = .open
        openedAt = Date()
    }
}