import Foundation

public struct ConsoleUI {
    
    /// A simple ANSI progress bar.
    public class ProgressBar: @unchecked Sendable {
        private let width: Int
        private let title: String
        private var lastPercentage: Int = -1
        
        public init(title: String, width: Int = 40) {
            self.title = title
            self.width = width
            // Initial render
            render(percentage: 0.0)
        }
        
        public func update(progress: Double) {
            let percentage = Int(min(1.0, max(0.0, progress)) * 100)
            
            // Only re-draw if percentage changed to avoid flicker/overhead
            if percentage != lastPercentage {
                render(percentage: progress)
                lastPercentage = percentage
            }
        }
        
        public func complete() {
            render(percentage: 1.0)
            print() // New line
        }
        
        private func render(percentage: Double) {
            let filledWidth = Int(Double(width) * percentage)
            let emptyWidth = width - filledWidth
            
            let bar = String(repeating: "=", count: filledWidth) + String(repeating: " ", count: emptyWidth)
            let percentStr = String(format: "%3d%%", Int(percentage * 100))
            
            // \r returns to start of line, allowing overwrite
            print("\r\(title) [\(bar)] \(percentStr)", terminator: "")
            fflush(stdout)
        }
    }
}
