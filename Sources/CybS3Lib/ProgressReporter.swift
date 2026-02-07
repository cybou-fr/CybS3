import Foundation

/// Enhanced progress reporting with metrics integration.
public class ProgressReporter {
    private let progressBar: ConsoleUI.ProgressBar
    private let startTime: Date
    private var lastUpdate: Date
    private var operationsCompleted: Int = 0
    private var bytesProcessed: Int64 = 0
    
    /// Progress event types.
    public enum ProgressEvent {
        case started(operation: String, totalItems: Int?)
        case progress(completed: Int, total: Int?, bytesProcessed: Int64?, details: String?)
        case completed(operation: String, duration: TimeInterval, bytesProcessed: Int64)
        case failed(operation: String, error: Error, duration: TimeInterval)
        case cancelled(operation: String, duration: TimeInterval)
    }
    
    /// Initialize a new progress reporter.
    ///
    /// - Parameters:
    ///   - title: The title for the progress display.
    ///   - showSpeed: Whether to show transfer speed.
    public init(title: String, showSpeed: Bool = true) {
        self.progressBar = ConsoleUI.ProgressBar(title: title, showSpeed: showSpeed)
        self.startTime = Date()
        self.lastUpdate = Date()
    }
    
    /// Report a progress event.
    ///
    /// - Parameter event: The progress event to report.
    public func report(_ event: ProgressEvent) {
        let now = Date()
        let elapsed = now.timeIntervalSince(startTime)
        
        switch event {
        case .started(let operation, let totalItems):
            CybS3Logger.log(.info, "Started operation: \(operation)")
            // ProgressBar starts automatically on init, no need for start() call
            
        case .progress(let completed, let total, let bytes, let details):
            operationsCompleted = completed
            if let bytes = bytes {
                bytesProcessed = bytes
            }
            
            let progress = total.map { Double(completed) / Double($0) } ?? 0.0
            var statusText = ""
            
            if let total = total {
                statusText = "\(completed)/\(total)"
            } else {
                statusText = "\(completed) items"
            }
            
            if let details = details {
                statusText += " - \(details)"
            }
            
            // Calculate speed if we have byte information
            let speed: Double?
            if bytesProcessed > 0 && elapsed > 0.5 {
                speed = Double(bytesProcessed) / elapsed
            } else {
                speed = nil
            }
            
            progressBar.update(progress: progress, bytesProcessed: bytes)
            
        case .completed(let operation, let duration, let bytes):
            bytesProcessed = bytes
            progressBar.complete()
            
            let speed = duration > 0 ? Double(bytes) / duration : 0
            let speedText = formatSpeed(bytesPerSecond: speed)
            
            CybS3Logger.log(.info, "Completed operation: \(operation)", metadata: [
                "duration": .string(String(format: "%.2f", duration) + "s"),
                "bytes_processed": .string("\(bytes)"),
                "speed": .string(speedText),
                "operations_completed": .string("\(operationsCompleted)")
            ])
            
            Metrics.recordOperation(operation, duration: duration, success: true)
            Metrics.recordBytesProcessed(bytes, operation: operation)
            
        case .failed(let operation, let error, let duration):
            progressBar.complete() // ProgressBar doesn't have fail(), so complete it
            
            CybS3Logger.log(.error, "Failed operation: \(operation)", metadata: [
                "duration": .string(String(format: "%.2f", duration) + "s"),
                "error": .string(error.localizedDescription)
            ])
            
            Metrics.recordOperation(operation, duration: duration, success: false)
            Metrics.recordError(error, operation: operation)
            
        case .cancelled(let operation, let duration):
            progressBar.complete() // ProgressBar doesn't have cancel(), so complete it
            
            CybS3Logger.log(.warning, "Cancelled operation: \(operation)", metadata: [
                "duration": .string(String(format: "%.2f", duration) + "s")
            ])
        }
        
        lastUpdate = now
    }
    
    /// Format bytes per second into human-readable string.
    private func formatSpeed(bytesPerSecond: Double) -> String {
        let units = ["B/s", "KB/s", "MB/s", "GB/s"]
        var speed = bytesPerSecond
        var unitIndex = 0
        
        while speed >= 1024 && unitIndex < units.count - 1 {
            speed /= 1024
            unitIndex += 1
        }
        
        return String(format: "%.1f %@", speed, units[unitIndex])
    }
    
    /// Get current statistics.
    public var statistics: (elapsed: TimeInterval, operationsCompleted: Int, bytesProcessed: Int64) {
        (Date().timeIntervalSince(startTime), operationsCompleted, bytesProcessed)
    }
}