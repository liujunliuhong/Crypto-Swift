//
//  Crypto.swift
//  BlockChain
//
//  Created by galaxy on 2021/8/26.
//

import Foundation

public struct Crypto {
    public static func dataToBytes(data: Data) -> [UInt8] {
        return [UInt8](data)
    }
    
    public static func randomData(length: Int) -> Data? {
        for _ in 0...1024 {
            var data = Data(repeating: 0, count: length)
            let result = data.withUnsafeMutableBytes { (body: UnsafeMutableRawBufferPointer) -> Int32? in
                if let bodyAddress = body.baseAddress, body.count > 0 {
                    let pointer = bodyAddress.assumingMemoryBound(to: UInt8.self)
                    return SecRandomCopyBytes(kSecRandomDefault, length, pointer)
                } else {
                    return nil
                }
            }
            if let notNilResult = result, notNilResult == errSecSuccess {
                return data
            }
        }
        return nil
    }
}
