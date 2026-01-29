import SwiftBIP39

let mnemonic = Mnemonic.generate()
print(mnemonic.joined(separator: " "))