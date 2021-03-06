//
//  SHA256.swift
//  SwiftTool
//
//  Created by liujun on 2021/5/28.
//  Copyright © 2021 yinhe. All rights reserved.
//

import Foundation
import CommonCrypto

extension Crypto {
    public struct SHA256 { }
}

extension Crypto.SHA256 {
    /// SHA256
    public static func sha256(data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) // 是否需要考虑data.count大于CC_LONG.max的情况?
        }
        return Data(hash)
    }
    
    /// SHA256
    public static func sha256(bytes: [UInt8]) -> Data {
        return Crypto.SHA256.sha256(data: Data(bytes))
    }
    
    /// SHA256 + SHA256
    public static func sha256sha256(data: Data) -> Data {
        var hash = Crypto.SHA256.sha256(data: data)
        hash = Crypto.SHA256.sha256(data: hash)
        return hash
    }
    
    /// SHA256 + SHA256
    public static func sha256sha256(bytes: [UInt8]) -> Data {
        return Crypto.SHA256.sha256sha256(data: Data(bytes))
    }
}
