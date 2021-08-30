//
//  ED25519.swift
//  BlockChain
//
//  Created by galaxy on 2021/8/26.
//

import Foundation
import libed25519

extension Crypto {
    public struct ED25519 { }
}

extension Crypto.ED25519 {
    public static func keypair() -> (privateKey: Data, publicKey: Data)? {
        guard let seed = Crypto.randomData(length: 32) else { return nil }
        let seedBytes = [UInt8](seed)
        
        var pub = [UInt8](Data(repeating: 0x00, count: 32))
        
        var pri: [UInt8] = []
        pri += seedBytes
        pri += [UInt8](repeating: 0x00, count: 32)
        
        crypto_sign_keypair(&pub, &pri)
        
        return (Data(pri), Data(pub))
    }
    
    public static func privateKeyToPublicKey(privateKey: Data?) -> Data? {
        guard let privateKey = privateKey else { return nil }
        guard let seed = Crypto.randomData(length: 32) else { return nil }
        var pub = [UInt8](seed)
        var pri = [UInt8](privateKey)
        crypto_sign_keypair(&pub, &pri)
        return Data(pub)
    }
    
    public static func sign(message: Data?, privateKey: Data?) -> Data? {
        guard let message = message else { return nil }
        guard message.count == 32 else { return nil }
        guard let privateKey = privateKey else { return nil }
        var priBytes = [UInt8](privateKey)
        var messageBytes = [UInt8](message)
        var sigLen: UInt64 = UInt64(64 + messageBytes.count)
        var sig = [UInt8](repeating: 0x00, count: Int(sigLen))
        
        crypto_sign(&sig, &sigLen, &messageBytes, UInt64(messageBytes.count), &priBytes)
        
        sig = Array(sig.prefix(64))
        
        return Data(sig)
    }
    
    public static func verify(message: Data?, signature: Data?, publicKey: Data?) -> Bool {
        guard let message = message else { return false }
        guard message.count == 32 else { return false }
        guard let signature = signature else { return false }
        guard let publicKey = publicKey else { return false }
        
        var pubBytes = [UInt8](publicKey)
        var messageBytes = [UInt8](message)
        var signatureBytes = [UInt8](signature)
        
        let result = crypto_sign_verify(&signatureBytes, &messageBytes, messageBytes.count, &pubBytes)
        return result == 0
    }
}
