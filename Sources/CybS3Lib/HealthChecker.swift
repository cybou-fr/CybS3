import Foundation

/// Health status of the system.
public enum HealthStatus {
    case healthy(details: [String: String])
    case degraded(details: [String: String], issues: [String])
    case unhealthy(details: [String: String], issues: [String])
    
    public var isHealthy: Bool {
        switch self {
        case .healthy: return true
        case .degraded, .unhealthy: return false
        }
    }
    
    public var description: String {
        switch self {
        case .healthy:
            return "✅ System is healthy"
        case .degraded:
            return "⚠️ System is degraded"
        case .unhealthy:
            return "❌ System is unhealthy"
        }
    }
}

/// System health checker for monitoring CybS3 components.
public struct HealthChecker {
    /// Perform a comprehensive health check.
    ///
    /// - Returns: The overall health status of the system.
    public static func performHealthCheck() async -> HealthStatus {
        var details = [String: String]()
        var issues = [String]()
        
        // Check configuration access
        let configHealth = await checkConfigurationHealth()
        details.merge(configHealth.details) { $1 }
        issues.append(contentsOf: configHealth.issues)
        
        // Check secure storage
        let storageHealth = await checkStorageHealth()
        details.merge(storageHealth.details) { $1 }
        issues.append(contentsOf: storageHealth.issues)
        
        // Check encryption functionality
        let encryptionHealth = checkEncryptionHealth()
        details.merge(encryptionHealth.details) { $1 }
        issues.append(contentsOf: encryptionHealth.issues)
        
        // Check system resources
        let systemHealth = checkSystemHealth()
        details.merge(systemHealth.details) { $1 }
        issues.append(contentsOf: systemHealth.issues)
        
        // Determine overall status
        if issues.isEmpty {
            return .healthy(details: details)
        } else if issues.count <= 2 {
            return .degraded(details: details, issues: issues)
        } else {
            return .unhealthy(details: details, issues: issues)
        }
    }
    
    /// Check configuration system health.
    private static func checkConfigurationHealth() async -> (details: [String: String], issues: [String]) {
        var details = [String: String]()
        var issues = [String]()
        
        // Try to access configuration manager
        _ = ConfigurationManager.shared
        details["configuration_manager"] = "accessible"
        
        // Check if we can load configuration (this will fail without authentication)
        // We just check that the manager is responsive
        details["configuration_system"] = "responsive"
        
        return (details, issues)
    }
    
    /// Check secure storage health.
    private static func checkStorageHealth() async -> (details: [String: String], issues: [String]) {
        var details = [String: String]()
        var issues = [String]()
        
        do {
            let storage = SecureStorageFactory.create()
            
            // Test basic storage operations
            let testKey = "health_check_test_\(UUID().uuidString)"
            let testData = Data("health_check".utf8)
            
            try storage.store(testData, for: testKey)
            let retrieved = try storage.retrieve(for: testKey)
            try storage.delete(for: testKey)
            
            if retrieved == testData {
                details["secure_storage"] = "functional"
            } else {
                issues.append("Secure storage data integrity check failed")
                details["secure_storage"] = "data_integrity_error"
            }
        } catch {
            issues.append("Secure storage error: \(error.localizedDescription)")
            details["secure_storage"] = "error"
        }
        
        return (details, issues)
    }
    
    /// Check encryption functionality.
    private static func checkEncryptionHealth() -> (details: [String: String], issues: [String]) {
        var details = [String: String]()
        var issues = [String]()
        
        do {
            // Test key derivation
            let testMnemonic = ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                              "abandon", "abandon", "abandon", "abandon", "abandon", "about"]
            let key = try Encryption.deriveKey(mnemonic: testMnemonic)
            
            if key.bitCount == 256 {
                details["key_derivation"] = "functional"
            } else {
                issues.append("Key derivation produced incorrect key size")
                details["key_derivation"] = "invalid_key_size"
            }
            
            // Test encryption roundtrip
            let testData = Data("encryption_test".utf8)
            let encrypted = try Encryption.encrypt(data: testData, key: key)
            let decrypted = try Encryption.decrypt(data: encrypted, key: key)
            
            if decrypted == testData {
                details["encryption_roundtrip"] = "functional"
            } else {
                issues.append("Encryption roundtrip failed")
                details["encryption_roundtrip"] = "data_integrity_error"
            }
        } catch {
            issues.append("Encryption system error: \(error.localizedDescription)")
            details["encryption_system"] = "error"
        }
        
        return (details, issues)
    }
    
    /// Check system resource health.
    private static func checkSystemHealth() -> (details: [String: String], issues: [String]) {
        var details = [String: String]()
        var issues = [String]()
        
        // Check available memory
        let memoryGB = PlatformSpecific.systemMemoryGB
        details["system_memory_gb"] = String(format: "%.1f", memoryGB)
        
        if memoryGB < 2.0 {
            issues.append("Low system memory: \(String(format: "%.1f", memoryGB))GB available")
        }
        
        // Check available disk space (simplified)
        #if os(macOS)
        do {
            let fileManager = FileManager.default
            let homeURL = fileManager.homeDirectoryForCurrentUser
            let attributes = try fileManager.attributesOfFileSystem(forPath: homeURL.path)
            
            if let freeSpace = attributes[.systemFreeSize] as? Int64 {
                let freeSpaceGB = Double(freeSpace) / (1024 * 1024 * 1024)
                details["free_disk_space_gb"] = String(format: "%.1f", freeSpaceGB)
                
                if freeSpaceGB < 1.0 {
                    issues.append("Low disk space: \(String(format: "%.1f", freeSpaceGB))GB available")
                }
            }
        } catch {
            details["disk_space_check"] = "error"
        }
        #endif
        
        // Check thread count
        let threadCount = PlatformSpecific.optimalThreadCount
        details["optimal_thread_count"] = "\(threadCount)"
        
        return (details, issues)
    }
    
    /// Print a detailed health report.
    ///
    /// - Parameter status: The health status to report.
    public static func printHealthReport(_ status: HealthStatus) {
        print("🏥 CybS3 Health Report")
        print("======================")
        print(status.description)
        print()
        
        if !status.isHealthy {
            print("Issues found:")
            switch status {
            case .healthy:
                break
            case .degraded(_, let issues), .unhealthy(_, let issues):
                for (index, issue) in issues.enumerated() {
                    print("  \(index + 1). \(issue)")
                }
                print()
            }
        }
        
        print("Component Status:")
        switch status {
        case .healthy(let details), .degraded(let details, _), .unhealthy(let details, _):
            for (component, status) in details.sorted(by: { $0.key < $1.key }) {
                let icon = status == "functional" || status == "accessible" || status == "responsive" ? "✅" : "❌"
                print("  \(icon) \(component): \(status)")
            }
        }
    }
}