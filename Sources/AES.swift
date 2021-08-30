//
//  AES.swift
//  Galaxy
//
//  Created by liujun on 2021/5/29.
//

import Foundation
import CryptoSwift

extension Crypto {
    public struct AES {
        public enum BlockMode {
            case cbc
            case ctr
        }
    }
}

extension Crypto.AES {
    /// AES加密
    ///
    ///     会根据`key`的长度动态选着使用`AES128`、`AES192`、`AES256`
    ///     当`key`的长度为`16`，使用`AES128`
    ///     当`key`的长度为`24`，使用`AES192`
    ///     当`key`的长度为`32`，使用`AES256`
    public static func encrypt(contentData: Data?, key: Data, iv: Data, blockMode: Crypto.AES.BlockMode, padding: CryptoSwift.Padding) -> Data? {
        guard let contentData = contentData else { return nil }
        var aesCipher: CryptoSwift.AES?
        switch blockMode {
            case .cbc:
                aesCipher = try? CryptoSwift.AES(key: [UInt8](key), blockMode: CBC(iv: [UInt8](iv)), padding: padding)
            case .ctr:
                aesCipher = try? CryptoSwift.AES(key: [UInt8](key), blockMode: CTR(iv: [UInt8](iv)), padding: padding)
        }
        if aesCipher == nil { return nil }
        
        guard let encryptedBytes = try? aesCipher?.encrypt([UInt8](contentData)) else { return nil }
        return Data(encryptedBytes)
    }
    
    /// AES解密
    ///
    ///     会根据`key`的长度动态选着使用`AES128`、`AES192`、`AES256`
    ///     当`key`的长度为`16`，使用`AES128`
    ///     当`key`的长度为`24`，使用`AES192`
    ///     当`key`的长度为`32`，使用`AES256`
    public static func decrypt(encryptedData: Data?, key: Data, iv: Data, blockMode: Crypto.AES.BlockMode, padding: CryptoSwift.Padding) -> Data? {
        guard let encryptedData = encryptedData else { return nil }
        var aesCipher: CryptoSwift.AES?
        switch blockMode {
            case .cbc:
                aesCipher = try? CryptoSwift.AES(key: [UInt8](key), blockMode: CBC(iv: [UInt8](iv)), padding: padding)
            case .ctr:
                aesCipher = try? CryptoSwift.AES(key: [UInt8](key), blockMode: CTR(iv: [UInt8](iv)), padding: padding)
        }
        if aesCipher == nil { return nil }
        guard let contentBytes = try? aesCipher!.decrypt([UInt8](encryptedData)) else { return nil }
        return Data(contentBytes)
    }
}
