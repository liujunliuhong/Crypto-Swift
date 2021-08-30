//
//  SHA512.swift
//  BlockChain
//
//  Created by galaxy on 2021/7/28.
//

import Foundation
import CommonCrypto

extension Crypto {
    public struct SHA512 { }
}

extension Crypto.SHA512 {
    /// SHA512
    public static func sha512(data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA512($0.baseAddress, CC_LONG(data.count), &hash) // 是否需要考虑data.count大于CC_LONG.max的情况?
        }
        return Data(hash)
    }
    
    /// SHA512
    public static func sha512(bytes: [UInt8]) -> Data {
        return Crypto.SHA512.sha512(data: Data(bytes))
    }
    
    /// SHA512 + SHA512
    public static func sha512sha512(data: Data) -> Data {
        var hash = Crypto.SHA512.sha512(data: data)
        hash = Crypto.SHA512.sha512(data: hash)
        return hash
    }
    
    /// SHA512 + SHA512
    public static func sha512sha512(bytes: [UInt8]) -> Data {
        return Crypto.SHA512.sha512sha512(data: Data(bytes))
    }
}
