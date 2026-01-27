import Foundation
import ArgumentParser
import AsyncHTTPClient

@main
struct CybS3: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "cybs3",
        abstract: "S3 Compatible Object Storage Browser",
        subcommands: [
            List.self,
            Get.self,
            Put.self,
            Delete.self,
            Mb.self,
            Rb.self,
            Ls.self,
            Config.self
        ],
        defaultSubcommand: Ls.self
    )
    
    struct GlobalOptions: ParsableArguments {
        @Option(name: .shortAndLong, help: "S3 endpoint URL")
        var endpoint: String = "s3.amazonaws.com"
        
        @Option(name: .shortAndLong, help: "Access key")
        var accessKey: String?
        
        @Option(name: .shortAndLong, help: "Secret key")
        var secretKey: String?
        
        @Option(name: .shortAndLong, help: "Bucket name")
        var bucket: String?
        
        @Option(name: .shortAndLong, help: "Region")
        var region: String = "us-east-1"
        
        @Flag(name: .shortAndLong, help: "Use SSL")
        var ssl: Bool = true
        
        @Flag(name: .shortAndLong, help: "Verbose output")
        var verbose: Bool = false
        
        func createClient() throws -> S3Client {
            let config = try loadConfig()
            
            let endpointURL = URL(string: endpoint) ?? URL(string: "https://\(endpoint)")!
            let host = endpointURL.host ?? endpoint
            let port = endpointURL.port ?? (ssl ? 443 : 80)
            let useSSL = endpointURL.scheme == "https" || ssl
            
            let s3Endpoint = S3Endpoint(
                host: host,
                port: port,
                useSSL: useSSL
            )
            
            let accessKey = accessKey ?? config.accessKey ?? ""
            let secretKey = secretKey ?? config.secretKey ?? ""
            let bucket = bucket ?? config.bucket
            
            return S3Client(
                endpoint: s3Endpoint,
                accessKey: accessKey,
                secretKey: secretKey,
                bucket: bucket,
                region: region
            )
        }
        
        private func loadConfig() throws -> Config {
            let configPath = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(".cybs3")
                .appendingPathExtension("json")
            
            guard FileManager.default.fileExists(atPath: configPath.path) else {
                return Config()
            }
            
            let data = try Data(contentsOf: configPath)
            return try JSONDecoder().decode(Config.self, from: data)
        }
    }
    
    struct Config: Codable {
        var accessKey: String?
        var secretKey: String?
        var endpoint: String?
        var region: String?
        var bucket: String?
    }
}

// MARK: - List Command

extension CybS3 {
    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "list",
            abstract: "List all buckets"
        )
        
        @OptionGroup var options: GlobalOptions
        
        func run() async throws {
            let client = try options.createClient()
            let buckets = try await client.listBuckets()
            
            print("Buckets:")
            for bucket in buckets {
                print("  \(bucket)")
            }
        }
    }
}

// MARK: - Get Command

extension CybS3 {
    struct Get: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "get",
            abstract: "Download an object from S3"
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Object key to download")
        var key: String
        
        @Option(name: .shortAndLong, help: "Output file path")
        var output: String?
        
        func run() async throws {
            guard options.bucket != nil else {
                print("Error: Bucket must be specified for get operation")
                throw ExitCode.failure
            }
            
            let client = try options.createClient()
            let data = try await client.getObject(key: key)
            
            let outputPath = output ?? FileManager.default.currentDirectoryPath + "/" + (key as NSString).lastPathComponent
            
            try data.write(to: URL(fileURLWithPath: outputPath))
            print("Downloaded \(key) to \(outputPath)")
        }
    }
}

// MARK: - Put Command

extension CybS3 {
    struct Put: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "put",
            abstract: "Upload a file to S3"
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Local file path to upload")
        var file: String
        
        @Argument(help: "S3 object key (optional)")
        var key: String?
        
        func run() async throws {
            guard options.bucket != nil else {
                print("Error: Bucket must be specified for put operation")
                throw ExitCode.failure
            }
            
            let fileURL = URL(fileURLWithPath: file)
            let data = try Data(contentsOf: fileURL)
            
            let objectKey = key ?? fileURL.lastPathComponent
            
            let client = try options.createClient()
            try await client.putObject(key: objectKey, data: data)
            
            print("Uploaded \(file) to \(objectKey)")
        }
    }
}

// MARK: - Delete Command

extension CybS3 {
    struct Delete: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "delete",
            abstract: "Delete an object from S3"
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Object key to delete")
        var key: String
        
        func run() async throws {
            guard options.bucket != nil else {
                print("Error: Bucket must be specified for delete operation")
                throw ExitCode.failure
            }
            
            let client = try options.createClient()
            try await client.deleteObject(key: key)
            
            print("Deleted \(key)")
        }
    }
}

// MARK: - Make Bucket Command

extension CybS3 {
    struct Mb: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "mb",
            abstract: "Create a new bucket"
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Bucket name to create")
        var bucket: String
        
        func run() async throws {
            let client = try options.createClient()
            try await client.createBucket(name: bucket)
            
            print("Created bucket: \(bucket)")
        }
    }
}

// MARK: - Remove Bucket Command

extension CybS3 {
    struct Rb: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "rb",
            abstract: "Remove a bucket (not implemented - requires bucket to be empty)"
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Bucket name to remove")
        var bucket: String
        
        func run() async throws {
            print("Note: Removing buckets requires the bucket to be empty first")
            print("Use: cybs3 list to see objects, then delete them before removing bucket")
        }
    }
}

// MARK: - List Objects Command (default)

extension CybS3 {
    struct Ls: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "ls",
            abstract: "List objects in a bucket",
            shouldDisplay: false
        )
        
        @OptionGroup var options: GlobalOptions
        
        @Argument(help: "Path prefix (optional)")
        var path: String?
        
        func run() async throws {
            guard options.bucket != nil else {
                print("Error: Bucket must be specified")
                print("Use: cybs3 --bucket <bucket-name> ls")
                throw ExitCode.failure
            }
            
            let client = try options.createClient()
            let objects = try await client.listObjects(prefix: path)
            
            for object in objects {
                print(object)
            }
        }
    }
}

// MARK: - Config Command

extension CybS3 {
    struct Config: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "config",
            abstract: "Configure CybS3"
        )
        
        @Option(name: .shortAndLong, help: "Set access key")
        var accessKey: String?
        
        @Option(name: .shortAndLong, help: "Set secret key")
        var secretKey: String?
        
        @Option(name: .shortAndLong, help: "Set default endpoint")
        var endpoint: String?
        
        @Option(name: .shortAndLong, help: "Set default region")
        var region: String?
        
        @Option(name: .shortAndLong, help: "Set default bucket")
        var bucket: String?
        
        func run() async throws {
            let configPath = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(".cybs3")
                .appendingPathExtension("json")
            
            var config = CybS3.Config()
            
            if FileManager.default.fileExists(atPath: configPath.path) {
                let data = try Data(contentsOf: configPath)
                config = try JSONDecoder().decode(CybS3.Config.self, from: data)
            }
            
            if let accessKey = accessKey {
                config.accessKey = accessKey
            }
            
            if let secretKey = secretKey {
                config.secretKey = secretKey
            }
            
            if let endpoint = endpoint {
                config.endpoint = endpoint
            }
            
            if let region = region {
                config.region = region
            }
            
            if let bucket = bucket {
                config.bucket = bucket
            }
            
            let data = try JSONEncoder().encode(config)
            try data.write(to: configPath)
            
            print("Configuration saved to \(configPath.path)")
        }
    }
}