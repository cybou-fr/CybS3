import Foundation

/// Interactive help system for contextual command assistance.
public struct InteractiveHelp {
    /// Show contextual help based on current command and arguments.
    ///
    /// - Parameters:
    ///   - command: The command being executed.
    ///   - args: The arguments passed to the command.
    public static func showContextualHelp(for command: String, args: [String]) {
        let help = generateHelp(for: command, args: args)
        print(help)
    }
    
    /// Generate help text for a specific command and context.
    private static func generateHelp(for command: String, args: [String]) -> String {
        var help = "💡 CybS3 Help - \(command.capitalized)\n\n"
        
        switch command.lowercased() {
        case "vaults", "vault":
            help += generateVaultsHelp(args: args)
        case "keys", "key":
            help += generateKeysHelp(args: args)
        case "ls", "list":
            help += generateListHelp(args: args)
        case "cp", "copy":
            help += generateCopyHelp(args: args)
        case "rm", "remove", "delete":
            help += generateDeleteHelp(args: args)
        case "sync":
            help += generateSyncHelp(args: args)
        case "login":
            help += generateLoginHelp()
        default:
            help += generateGeneralHelp()
        }
        
        help += "\n📖 For more information, see: https://github.com/cybou-fr/CybS3\n"
        return help
    }
    
    private static func generateVaultsHelp(args: [String]) -> String {
        if args.contains("add") {
            return """
            Adding a new vault:
            
            1. Choose a unique vault name
            2. Provide your S3 endpoint (e.g., s3.amazonaws.com)
            3. Enter your access key and secret key
            4. Specify the bucket name and region
            
            Example:
              cybs3 vaults add --name myvault
            
            Tip: Use 'cybs3 vaults list' to see existing vaults.
            """
        } else if args.contains("select") {
            return """
            Selecting a vault:
            
            • Use 'cybs3 vaults select <name>' to set the active vault
            • All subsequent commands will use this vault
            • Use 'cybs3 vaults list' to see available vaults
            
            Example:
              cybs3 vaults select myvault
            """
        } else {
            return """
            Vault management commands:
            
            • vaults add     - Create a new encrypted vault
            • vaults list    - Show all configured vaults
            • vaults select  - Set the active vault
            • vaults delete  - Remove a vault configuration
            
            Tip: Vaults store your S3 credentials securely.
            """
        }
    }
    
    private static func generateKeysHelp(args: [String]) -> String {
        if args.contains("create") {
            return """
            Creating a new mnemonic:
            
            1. Run 'cybs3 keys create' to generate a 12-word mnemonic
            2. Write down all words in order - this is your master key
            3. Store the mnemonic securely (paper, hardware wallet, etc.)
            4. Use 'cybs3 login' to authenticate with the mnemonic
            
            ⚠️  WARNING: Never store your mnemonic digitally!
            ⚠️  Loss of mnemonic means loss of all encrypted data!
            """
        } else {
            return """
            Key management commands:
            
            • keys create   - Generate a new 12-word mnemonic
            • keys show     - Display current mnemonic (masked)
            
            Tip: Your mnemonic is the master key to all your data.
            """
        }
    }
    
    private static func generateListHelp(args: [String]) -> String {
        return """
        Listing objects:
        
        • Use 'cybs3 ls' to list objects in the current vault
        • Add a path to list specific directories
        • Use --long for detailed information
        
        Examples:
          cybs3 ls
          cybs3 ls documents/
          cybs3 ls --long
        
        Tip: Use '/' at the end to list directory contents.
        """
    }
    
    private static func generateCopyHelp(args: [String]) -> String {
        return """
        Copying files:
        
        • 'cybs3 cp <local> <remote>' - Upload local file
        • 'cybs3 cp <remote> <local>' - Download remote file
        
        Examples:
          cybs3 cp document.pdf s3://mybucket/docs/
          cybs3 cp s3://mybucket/photo.jpg ./downloads/
        
        Options:
          --recursive  - Copy directories recursively
          --overwrite  - Overwrite existing files
        
        Tip: Remote paths should start with 's3://'
        """
    }
    
    private static func generateDeleteHelp(args: [String]) -> String {
        return """
        Deleting objects:
        
        • 'cybs3 rm <path>' - Delete a single object
        • 'cybs3 rm --recursive <path>' - Delete directory
        
        Examples:
          cybs3 rm document.pdf
          cybs3 rm --recursive old-folder/
        
        ⚠️  WARNING: Deletion is permanent and cannot be undone!
        
        Tip: Use 'cybs3 ls' first to verify what you're deleting.
        """
    }
    
    private static func generateSyncHelp(args: [String]) -> String {
        return """
        Synchronizing directories:
        
        • 'cybs3 sync <local> <remote>' - Sync local to remote
        • 'cybs3 sync <remote> <local>' - Sync remote to local
        
        Examples:
          cybs3 sync ./docs s3://mybucket/backup/
          cybs3 sync s3://mybucket/photos ./downloads/
        
        The sync command will:
        • Upload new/changed local files
        • Download new/changed remote files
        • Skip identical files
        
        Tip: Sync is bidirectional - changes flow both ways.
        """
    }
    
    private static func generateLoginHelp() -> String {
        return """
        Authentication:
        
        • Run 'cybs3 login' to authenticate with your mnemonic
        • Enter your 12-word mnemonic when prompted
        • Authentication is required before using other commands
        
        Tip: Use 'cybs3 login' after creating a new mnemonic.
        """
    }
    
    private static func generateGeneralHelp() -> String {
        return """
        CybS3 - Secure S3-compatible object storage with client-side encryption
        
        Getting started:
        1. Create a mnemonic: cybs3 keys create
        2. Login: cybs3 login
        3. Add a vault: cybs3 vaults add
        4. Start using: cybs3 ls, cybs3 cp, etc.
        
        Common commands:
        • login     - Authenticate with mnemonic
        • vaults    - Manage S3 vault configurations
        • ls        - List objects
        • cp        - Copy files to/from S3
        • rm        - Delete objects
        • sync      - Synchronize directories
        
        Use 'cybs3 <command> --help' for detailed command help.
        """
    }
}