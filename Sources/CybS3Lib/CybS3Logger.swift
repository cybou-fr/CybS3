import Foundation
import Logging

/// Centralized logging for CybS3 operations with structured logging support.
public struct CybS3Logger {
    /// The underlying Swift Logging logger instance.
    public static let logger = Logger(label: "com.cybs3.cli")
    
    /// Log levels for different types of messages.
    public enum LogLevel {
        case trace
        case debug
        case info
        case notice
        case warning
        case error
        case critical
    }
    
    /// Logs a message with the specified level and optional metadata.
    ///
    /// - Parameters:
    ///   - level: The log level.
    ///   - message: The message to log.
    ///   - metadata: Optional metadata to include with the log entry.
    public static func log(
        _ level: LogLevel,
        _ message: String,
        metadata: Logger.Metadata? = nil
    ) {
        let swiftLogLevel: Logger.Level
        switch level {
        case .trace: swiftLogLevel = .trace
        case .debug: swiftLogLevel = .debug
        case .info: swiftLogLevel = .info
        case .notice: swiftLogLevel = .notice
        case .warning: swiftLogLevel = .warning
        case .error: swiftLogLevel = .error
        case .critical: swiftLogLevel = .critical
        }
        
        logger.log(level: swiftLogLevel, "\(message)", metadata: metadata)
    }
    
    /// Logs the completion of an operation with timing information.
    ///
    /// - Parameters:
    ///   - operation: The name of the operation that completed.
    ///   - duration: The duration of the operation in seconds.
    ///   - success: Whether the operation was successful.
    ///   - metadata: Optional additional metadata.
    public static func logOperation(
        _ operation: String,
        duration: TimeInterval? = nil,
        success: Bool = true,
        metadata: Logger.Metadata = [:]
    ) {
        var finalMetadata = metadata
        if let duration = duration {
            finalMetadata["duration"] = "\(String(format: "%.3f", duration))s"
        }
        finalMetadata["success"] = "\(success)"
        
        let level: LogLevel = success ? .info : .error
        let message = "Operation '\(operation)' \(success ? "completed" : "failed")"
        
        log(level, message, metadata: finalMetadata)
    }
    
    /// Logs an error with context.
    ///
    /// - Parameters:
    ///   - error: The error that occurred.
    ///   - operation: The operation during which the error occurred.
    ///   - metadata: Optional additional metadata.
    public static func logError(
        _ error: Error,
        operation: String? = nil,
        metadata: Logger.Metadata = [:]
    ) {
        var finalMetadata = metadata
        finalMetadata["error_type"] = .string("\(type(of: error))")
        finalMetadata["error_description"] = .string(error.localizedDescription)
        if let operation = operation {
            finalMetadata["operation"] = .string(operation)
        }
        
        log(.error, "Error occurred: \(error.localizedDescription)", metadata: finalMetadata)
    }
    
    /// Creates a logger for a specific subsystem.
    ///
    /// - Parameter subsystem: The subsystem name.
    /// - Returns: A logger configured for the subsystem.
    public static func subsystemLogger(_ subsystem: String) -> Logger {
        Logger(label: "com.cybs3.\(subsystem)")
    }
}