import Foundation

public struct ConsoleUI {
    
    // MARK: - ANSI Color Codes
    
    public enum Color: String {
        case reset = "\u{001B}[0m"
        case red = "\u{001B}[31m"
        case green = "\u{001B}[32m"
        case yellow = "\u{001B}[33m"
        case blue = "\u{001B}[34m"
        case magenta = "\u{001B}[35m"
        case cyan = "\u{001B}[36m"
        case white = "\u{001B}[37m"
        case bold = "\u{001B}[1m"
        case dim = "\u{001B}[2m"
    }
    
    /// Whether to use ANSI colors (auto-detected based on terminal).
    /// Using nonisolated(unsafe) as this is intentionally mutable for testing/configuration purposes.
    nonisolated(unsafe) public static var useColors: Bool = {
        // Check if stdout is a TTY
        return isatty(STDOUT_FILENO) == 1
    }()
    
    /// Wraps text in ANSI color codes if colors are enabled.
    public static func colored(_ text: String, _ color: Color) -> String {
        guard useColors else { return text }
        return "\(color.rawValue)\(text)\(Color.reset.rawValue)"
    }
    
    // MARK: - Status Icons
    
    public enum StatusIcon {
        case success
        case error
        case warning
        case info
        case progress
        case question
        case key
        case folder
        case file
        case cloud
        case lock
        case unlock
        
        public var symbol: String {
            switch self {
            case .success: return "✅"
            case .error: return "❌"
            case .warning: return "⚠️"
            case .info: return "ℹ️"
            case .progress: return "⏳"
            case .question: return "❓"
            case .key: return "🔑"
            case .folder: return "📂"
            case .file: return "📄"
            case .cloud: return "☁️"
            case .lock: return "🔐"
            case .unlock: return "🔓"
            }
        }
    }
    
    // MARK: - Output Helpers
    
    /// Prints a success message.
    public static func success(_ message: String) {
        print("\(StatusIcon.success.symbol) \(colored(message, .green))")
    }
    
    /// Prints an error message to stderr.
    public static func error(_ message: String) {
        fputs("\(StatusIcon.error.symbol) \(colored(message, .red))\n", stderr)
    }
    
    /// Prints a warning message.
    public static func warning(_ message: String) {
        print("\(StatusIcon.warning.symbol) \(colored(message, .yellow))")
    }
    
    /// Prints an info message.
    public static func info(_ message: String) {
        print("\(StatusIcon.info.symbol) \(colored(message, .cyan))")
    }
    
    /// Prints a dimmed/secondary message.
    public static func dim(_ message: String) {
        print(colored(message, .dim))
    }
    
    /// Prints a section header.
    public static func header(_ title: String, width: Int = 50) {
        let line = String(repeating: "─", count: width)
        print(colored(line, .dim))
        print(colored(title, .bold))
        print(colored(line, .dim))
    }
    
    /// Prints a key-value pair.
    public static func keyValue(_ key: String, _ value: String, keyWidth: Int = 20) {
        let paddedKey = key.padding(toLength: keyWidth, withPad: " ", startingAt: 0)
        print("  \(colored(paddedKey, .dim)) \(value)")
    }
    
    // MARK: - Formatting Helpers
    
    /// Formats bytes into a human-readable string.
    public static func formatBytes(_ bytes: Int64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB", "PB"]
        var size = Double(bytes)
        var unitIndex = 0
        
        while size >= 1024 && unitIndex < units.count - 1 {
            size /= 1024
            unitIndex += 1
        }
        
        if unitIndex == 0 {
            return "\(bytes) B"
        }
        return String(format: "%.2f %@", size, units[unitIndex])
    }
    
    /// Formats a duration in seconds into a human-readable string.
    public static func formatDuration(_ seconds: TimeInterval) -> String {
        if seconds < 1 {
            return String(format: "%.0f ms", seconds * 1000)
        } else if seconds < 60 {
            return String(format: "%.1f s", seconds)
        } else if seconds < 3600 {
            let mins = Int(seconds / 60)
            let secs = Int(seconds.truncatingRemainder(dividingBy: 60))
            return "\(mins)m \(secs)s"
        } else {
            let hours = Int(seconds / 3600)
            let mins = Int((seconds.truncatingRemainder(dividingBy: 3600)) / 60)
            return "\(hours)h \(mins)m"
        }
    }
    
    /// Formats a date for display.
    public static func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }
    
    // MARK: - Table Rendering
    
    /// Prints a simple table.
    public static func table(headers: [String], rows: [[String]], columnWidths: [Int]? = nil) {
        let widths: [Int]
        if let columnWidths = columnWidths {
            widths = columnWidths
        } else {
            // Auto-calculate widths
            widths = headers.indices.map { i in
                let headerWidth = headers[i].count
                let maxRowWidth = rows.map { $0.indices.contains(i) ? $0[i].count : 0 }.max() ?? 0
                return max(headerWidth, maxRowWidth) + 2
            }
        }
        
        // Header
        let headerLine = headers.enumerated().map { (i, h) in
            h.padding(toLength: widths[i], withPad: " ", startingAt: 0)
        }.joined()
        print(colored(headerLine, .bold))
        
        // Separator
        let separator = widths.map { String(repeating: "─", count: $0) }.joined()
        print(colored(separator, .dim))
        
        // Rows
        for row in rows {
            let rowLine = row.enumerated().map { (i, cell) in
                cell.padding(toLength: widths.indices.contains(i) ? widths[i] : cell.count, withPad: " ", startingAt: 0)
            }.joined()
            print(rowLine)
        }
    }
    
    // MARK: - Progress Bar
    
    /// A simple ANSI progress bar with enhanced features.
    public class ProgressBar: @unchecked Sendable {
        private let width: Int
        private let title: String
        private var lastPercentage: Int = -1
        private let startTime: Date
        private var lastUpdate: Date
        private var bytesProcessed: Int64 = 0
        private let showSpeed: Bool
        private let lock = NSLock()
        
        public init(title: String, width: Int = 40, showSpeed: Bool = true) {
            self.title = title
            self.width = width
            self.showSpeed = showSpeed
            self.startTime = Date()
            self.lastUpdate = Date()
            // Initial render
            render(percentage: 0.0, speed: nil)
        }
        
        public func update(progress: Double, bytesProcessed: Int64? = nil) {
            lock.lock()
            defer { lock.unlock() }
            
            let percentage = Int(min(1.0, max(0.0, progress)) * 100)
            
            if let bytes = bytesProcessed {
                self.bytesProcessed = bytes
            }
            
            // Only re-draw if percentage changed to avoid flicker/overhead
            if percentage != lastPercentage {
                let elapsed = Date().timeIntervalSince(startTime)
                let speed: Double? = showSpeed && elapsed > 0.5 ? Double(self.bytesProcessed) / elapsed : nil
                render(percentage: progress, speed: speed)
                lastPercentage = percentage
                lastUpdate = Date()
            }
        }
        
        public func complete() {
            render(percentage: 1.0, speed: nil)
            let elapsed = Date().timeIntervalSince(startTime)
            print(" \(ConsoleUI.colored("(\(ConsoleUI.formatDuration(elapsed)))", .dim))")
        }
        
        private func render(percentage: Double, speed: Double?) {
            let filledWidth = Int(Double(width) * percentage)
            let emptyWidth = width - filledWidth
            
            let filled = ConsoleUI.useColors 
                ? "\(Color.green.rawValue)\(String(repeating: "█", count: filledWidth))\(Color.reset.rawValue)"
                : String(repeating: "=", count: filledWidth)
            let empty = ConsoleUI.useColors
                ? "\(Color.dim.rawValue)\(String(repeating: "░", count: emptyWidth))\(Color.reset.rawValue)"
                : String(repeating: " ", count: emptyWidth)
            
            let percentStr = String(format: "%3d%%", Int(percentage * 100))
            
            var line = "\r\(title) [\(filled)\(empty)] \(percentStr)"
            
            if let speed = speed, speed > 0 {
                line += " \(ConsoleUI.colored("(\(ConsoleUI.formatBytes(Int64(speed)))/s)", .dim))"
            }
            
            print(line, terminator: "")
            fflush(stdout)
        }
    }
    
    // MARK: - Spinner
    
    /// A simple spinner for indeterminate progress.
    public class Spinner {
        private let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        private var frameIndex = 0
        private let message: String
        private var isRunning = false
        private var timer: Timer?
        
        public init(message: String) {
            self.message = message
        }
        
        public func start() {
            guard !isRunning else { return }
            isRunning = true
            
            // Manual frame update since Timer requires RunLoop
            render()
        }
        
        public func stop(success: Bool = true) {
            isRunning = false
            let icon = success ? StatusIcon.success.symbol : StatusIcon.error.symbol
            print("\r\(icon) \(message)")
        }
        
        public func tick() {
            guard isRunning else { return }
            render()
        }
        
        private func render() {
            let frame = frames[frameIndex % frames.count]
            frameIndex += 1
            print("\r\(ConsoleUI.colored(frame, .cyan)) \(message)", terminator: "")
            fflush(stdout)
        }
    }
}
