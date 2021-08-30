//
//  Base64.swift
//  Galaxy
//
//  Created by liujun on 2021/5/29.
//

import Foundation

extension Crypto {
    public struct Base64 { }
}

extension Crypto.Base64 {
    
    /// `Base64`编码
    public static func base64Encoded(data: Data?, options: Data.Base64EncodingOptions = []) -> Data? {
        guard let data = data else { return nil }
        return data.base64EncodedData(options: options)
    }
    
    /// `Base64`解码
    public static func base64Decoded(data: Data?, options: Data.Base64DecodingOptions = []) -> Data? {
        guard let data = data else { return nil }
        return Data(base64Encoded: data, options: options)
    }
    
    /// `Base64`解码
    public static func base64Decoded(string: String?, options: Data.Base64DecodingOptions = []) -> Data? {
        guard let string = string else { return nil }
        var base64 = string.replacingOccurrences(of: "=", with: "")
        base64 += String(repeating: "=", count: base64.count % 4)
        return Data(base64Encoded: base64, options: options)
    }
}
