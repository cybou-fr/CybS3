import Foundation

/// Metrics collection for monitoring CybS3 operations.
public struct Metrics {
    /// Timer metric for operation durations.
    public static let operationDuration = TimerMetric(name: "cybs3_operation_duration")
    
    /// Counter metric for bytes processed.
    public static let bytesProcessed = CounterMetric(name: "cybs3_bytes_processed")
    
    /// Counter metric for errors.
    public static let errors = CounterMetric(name: "cybs3_errors_total")
    
    /// Records the duration of an operation.
    ///
    /// - Parameters:
    ///   - operation: The name of the operation.
    ///   - duration: The duration in seconds.
    ///   - success: Whether the operation was successful.
    public static func recordOperation(_ operation: String, duration: TimeInterval, success: Bool) {
        operationDuration.record(duration, labels: ["operation": operation, "success": success.description])
    }
    
    /// Records bytes processed.
    ///
    /// - Parameters:
    ///   - bytes: The number of bytes processed.
    ///   - operation: The operation type.
    public static func recordBytesProcessed(_ bytes: Int64, operation: String) {
        bytesProcessed.increment(by: UInt64(bytes), labels: ["operation": operation])
    }
    
    /// Records an error occurrence.
    ///
    /// - Parameters:
    ///   - error: The error that occurred.
    ///   - operation: The operation during which the error occurred.
    public static func recordError(_ error: Error, operation: String) {
        errors.increment(labels: [
            "operation": operation,
            "error_type": String(describing: type(of: error))
        ])
    }
}

/// Protocol for timer metrics.
public protocol TimerMetricProtocol {
    func record(_ duration: TimeInterval, labels: [String: String])
}

/// Protocol for counter metrics.
public protocol CounterMetricProtocol {
    func increment(by amount: UInt64, labels: [String: String])
}

/// Basic timer metric implementation.
public struct TimerMetric: TimerMetricProtocol, Sendable {
    public let name: String
    
    public init(name: String) {
        self.name = name
    }
    
    public func record(_ duration: TimeInterval, labels: [String: String] = [:]) {
        // In a real implementation, this would send to a metrics backend
        // For now, we just print for debugging
        #if DEBUG
        print("METRIC: \(name) = \(duration)s \(labels)")
        #endif
    }
}

/// Basic counter metric implementation.
public struct CounterMetric: CounterMetricProtocol, Sendable {
    public let name: String
    
    public init(name: String) {
        self.name = name
    }
    
    public func increment(by amount: UInt64 = 1, labels: [String: String] = [:]) {
        // In a real implementation, this would send to a metrics backend
        // For now, we just print for debugging
        #if DEBUG
        print("METRIC: \(name) += \(amount) \(labels)")
        #endif
    }
}