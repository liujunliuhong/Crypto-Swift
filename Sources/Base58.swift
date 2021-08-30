//
//  Base58.swift
//  SwiftTool
//
//  Created by liujun on 2021/5/27.
//  Copyright © 2021 yinhe. All rights reserved.
//

import Foundation
import CryptoSwift


/// `Base58`
/// `Base58`是用于`Bitcoin`中使用的一种独特的编码方式，主要用于产生`Bitcoin`的钱包地址。
/// 相比`Base64`，`Base58`不使用数字"0"，字母大写"O"，字母大写"I"，和字母小写"l"，以及"+"和"/"符号。
/// 本质其实就是58进制
/// https://www.cnblogs.com/yanglang/p/10147028.html
/// https://blog.csdn.net/bnbjin/article/details/81431686
/// https://blog.csdn.net/idwtwt/article/details/80740474
/// https://www.sohu.com/a/238347731_116580
/// https://www.liankexing.com/q/6455



/// `Base58 Check`
/// 1.首先对数据添加一个版本前缀，这个前缀用来识别编码的数据类型
/// 2.对数据连续进行两次`SHA256`哈希算法
/// checksum = SHA256(SHA256(prefix+data))
/// 3.在产生的长度为`32`个字节（两次哈希云算）的哈希值中，取其前`4`个字节作为检验和添加到数据第一步产生的数据之后
/// 4.将数据进行Base58编码处理
/// https://blog.csdn.net/luckydog612/article/details/81168276
/// https://www.jianshu.com/p/9644fe5a06bc
/// 地址前缀列表：https://en.bitcoin.it/wiki/List_of_address_prefixes


private let base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


extension Crypto {
    public struct Base58 { }
}

extension Crypto.Base58 {
    // `Base 58`编码
    public static func base58Encoded(data: Data) -> String {
        var bytes = [UInt8](data)
        var zerosCount = 0
        var length = 0
        
        for b in bytes {
            if b != 0 { break }
            zerosCount += 1
        }
        
        bytes.removeFirst(zerosCount)
        
        let size = bytes.count * 138 / 100 + 1
        
        var base58: [UInt8] = Array(repeating: 0, count: size)
        for b in bytes {
            var carry = Int(b)
            var i = 0
            
            for j in 0...base58.count-1 where carry != 0 || i < length {
                carry += 256 * Int(base58[base58.count - j - 1])
                base58[base58.count - j - 1] = UInt8(carry % 58)
                carry /= 58
                i += 1
            }
            
            assert(carry == 0)
            
            length = i
        }
        
        // skip leading zeros
        var zerosToRemove = 0
        var str = ""
        for b in base58 {
            if b != 0 { break }
            zerosToRemove += 1
        }
        base58.removeFirst(zerosToRemove)
        
        while 0 < zerosCount {
            str = "\(str)1"
            zerosCount -= 1
        }
        
        for b in base58 {
            str = "\(str)\(base58Alphabet[String.Index(utf16Offset: Int(b), in: base58Alphabet)])"
        }
        
        return str
    }
    
    // `Base 58`解码
    public static func base58Decoded(base58String: String) -> [UInt8] {
        // remove leading and trailing whitespaces
        let string = base58String.trimmingCharacters(in: CharacterSet.whitespaces)
        
        guard !string.isEmpty else { return [] }
        
        var zerosCount = 0
        var length = 0
        for c in string {
            if c != "1" { break }
            zerosCount += 1
        }
        
        let size = string.lengthOfBytes(using: String.Encoding.utf8) * 733 / 1000 + 1 - zerosCount
        var base58: [UInt8] = Array(repeating: 0, count: size)
        for c in string where c != " " {
            // search for base58 character
            guard let base58Index = base58Alphabet.firstIndex(of: c) else { return [] }
            
            //            var carry = base58Index.encodedOffset
            var carry = base58Index.utf16Offset(in: base58Alphabet)
            var i = 0
            for j in 0...base58.count where carry != 0 || i < length {
                carry += 58 * Int(base58[base58.count - j - 1])
                base58[base58.count - j - 1] = UInt8(carry % 256)
                carry /= 256
                i += 1
            }
            
            assert(carry == 0)
            length = i
        }
        
        // skip leading zeros
        var zerosToRemove = 0
        
        for b in base58 {
            if b != 0 { break }
            zerosToRemove += 1
        }
        base58.removeFirst(zerosToRemove)
        
        var result: [UInt8] = Array(repeating: 0, count: zerosCount)
        for b in base58 {
            result.append(b)
        }
        return result
    }
    
    /// `Base 58 Check`编码
    public static func base58CheckEncoded(data: Data?) -> String? {
        guard let data = data else { return nil }
        // 连续两次`SHA256`
        let checksums = Crypto.SHA256.sha256sha256(data: data)
        // 取前4位得到`checksum`
        let checksum = Array(checksums[0..<4])
        // 得到完整的`bytes`
        let resultData = data + checksum
        // Base58编码
        let base58String = Crypto.Base58.base58Encoded(data: resultData)
        return base58String
    }
    
    /// `Base 58 Check`解码
    public static func base58CheckDecoded(base58Data: Data?) -> Data? {
        let base58Data = base58Data ?? Data()
        guard let base58String = String(data: base58Data, encoding: .utf8) else { return nil }
        // 先解码
        var bytes = Crypto.Base58.base58Decoded(base58String: base58String)
        
        guard bytes.count > 4 else { return nil }
        
        let checksum = [UInt8](bytes.suffix(4))
        
        bytes = [UInt8](bytes.prefix(bytes.count - 4))
        
        
        var calculatedChecksum = Crypto.SHA256.sha256sha256(data: Data(bytes))
        calculatedChecksum = calculatedChecksum[0..<4]
        
        if checksum != [UInt8](calculatedChecksum) { return nil }
        
        return Data(bytes)
    }
    
    /// `Base 58 Check`解码
    public static func base58CheckDecoded(base58String: String?) -> Data? {
        guard let base58String = base58String else { return nil }
        guard let data = base58String.data(using: .utf8) else { return nil }
        return Crypto.Base58.base58CheckDecoded(base58Data: data)
    }
}



//    /// `Base 58`编码
//    public static func base58Encoded(data: Data) -> Data {
//        let base58AlphaBytes: [UInt8] = [UInt8](base58Alphabet.utf8)
//        // 58进制
//        let radix = BigUInt(base58AlphaBytes.count)
//        // 临时变量
//        var x = BigUInt(data)
//        // 存储转换结果
//        var result = [UInt8]()
//        // 分配足够的空间
//        // 这儿空间有点多余，通过查找资料，经过Base58编码的数据为原始的数据长度的1.37倍左右。此处给了2倍的空间
//        result.reserveCapacity(data.count + data.count)
//        // 循环遍历
//        while x > BigUInt(0) {
//            // x除以58，获取商和余数
//            let (quotient, remainder) = x.quotientAndRemainder(dividingBy: radix)
//            // 余数就是索引，根据索引取值，然后放进数组中
//            result.append(base58AlphaBytes[Int(remainder)])
//            // 重新赋值x，开始下一次循环
//            x = quotient
//        }
//        // 最前面的0
//        let zeroBytes = data.prefix { (value) -> Bool in
//            return value == 0
//        }.map { (_) -> UInt8 in
//            return base58AlphaBytes.first! // 1
//        }
//        result.append(contentsOf: zeroBytes)
//        // 翻转
//        result.reverse()
//
//        return Data(result)
//    }
//
//    /// `Base 58`解码
//    public static func base58Decoded(data: Data) -> Data? {
//        let base58AlphaBytes: [UInt8] = [UInt8](base58Alphabet.utf8)
//        // 58进制
//        let radix = BigUInt(base58AlphaBytes.count)
//        // 原始Data转换为byte
//        let bytes = [UInt8](data)
//        // 初始值
//        var result = BigUInt(0)
//        //
//        var j = BigUInt(1)
//        //
//        for ch in bytes.reversed() {
//            // 拿到对应的索引
//            if let index = base58AlphaBytes.firstIndex(of: ch) {
//                result = result + (j * BigUInt(index))
//                j *= radix
//            } else {
//                return nil
//            }
//        }
//        // 序列化
//        var resultData = result.serialize()
//        //
//        let zeroBytes = bytes.prefix { value in
//            return value == base58AlphaBytes.first! // 1
//        }
//        //
//        resultData = Data(zeroBytes) + resultData
//
//        return Data(resultData)
//    }
