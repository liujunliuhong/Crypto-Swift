//
//  SECP256K1.swift
//  Galaxy
//
//  Created by liujun on 2021/5/31.
//

import Foundation
import libsecp256k1

/// Hash
/// Hash，一般翻译做散列、杂凑，或音译为哈希
/// 是把任意长度的输入（又叫做预映射pre-image）通过散列算法变换成固定长度的输出，该输出就是散列值。
/// 这种转换是一种压缩映射，也就是，散列值的空间通常远小于输入的空间，不同的输入可能会散列成相同的输出，
/// 所以不可能从散列值来确定唯一的输入值。
/// 简单的说就是一种将任意长度的消息压缩到某一固定长度的消息摘要的函数。


/// `ECDSA`（`Elliptic Curve Digital Signature Algorithm`）
/// 椭圆曲线数字签名算法  `y² = (x³ + a.x + b) mod p`
/// 数字签名是一种数学方案，由两部分组成的：
/// 第一部分是使用私钥（签名密钥）从消息（交易）创建签名的算法；
/// 第二部分是允许任何人依据给定的消息和公钥验证签名的算法。
/// `ECDSA`用于对数据（比如一个文件）创建数字签名，以便于你在不破坏它的安全性的前提下对它的真实性进行验证。
/// 可以将它想象成一个实际的签名，你可以识别部分人的签名，但是你无法在别人不知道的情况下伪造它。
/// 而`ECDSA`签名和真实签名的区别在于，伪造`ECDSA`签名是根本不可能的
/// 你不应该将`ECDSA`与用来对数据进行加密的`AES`（高级加密标准）相混淆。
/// `ECDSA`不会对数据进行加密、或阻止别人看到或访问你的数据，它可以防止的是确保数据没有被篡改
/// `R = k * P`的性质，已知`R`与`P`的值，无法推出`k`的值, 而知道`k`值于`P`值是很容易计算`R`值。这是`ECDSA`签名算法的理论基础
/// https://zhuanlan.zhihu.com/p/97953640



/// SECP256K1
/// 比特币使用基于椭圆曲线加密的椭圆曲线数字签名算法（`ECDSA`）
/// 特定的椭圆曲线称为`secp256k1`，即曲线`y² = x³ + 7`


/// 椭圆曲线乘法是密码学家称为“陷阱门”的一种函数：在一个方向（乘法）很容易做到，而在相反方向（除法）不可能做到。
/// 私钥的所有者可以很容易地创建公钥，然后与世界共享，因为知道没有人能够反转该函数并从公钥计算私钥。
/// 这种数学技巧成为证明比特币资金所有权的不可伪造且安全的数字签名的基础。
/// http://www.secg.org/sec2-v2.pdf


extension Crypto {
    public struct SECP256K1 {
        private static let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY))
        
        public struct UnmarshaledSignature{
            public var v: UInt8 = 0
            public var r = Data(repeating: 0, count: 32)
            public var s = Data(repeating: 0, count: 32)
            
            public init(v: UInt8, r: Data, s: Data) {
                self.v = v
                self.r = r
                self.s = s
            }
        }
    }
}


extension Crypto.SECP256K1 {
    /// 根据`hash`和`私钥`得到签名的序列化数据
    public static func signatureDER(hash: Data?, privateKey: Data?, useExtraEntropy: Bool = true) -> Data? {
        guard let hash = hash else { return nil }
        guard let privateKey = privateKey else { return nil }
        guard hash.count == 32 else { return nil }
        guard privateKey.count == 32 else { return nil }
        // 验证私钥
        guard Crypto.SECP256K1.isValidPrivateKey(privateKey: privateKey) else { return nil }
        
        for _ in 0...1024 {
            guard var recoverableSignature: secp256k1_ecdsa_recoverable_signature = Crypto.SECP256K1._signForRecovery(hash: hash, privateKey: privateKey, useExtraEntropy: useExtraEntropy) else { continue }
            var signature = secp256k1_ecdsa_signature()
            // Convert a recoverable signature into a normal signature.
            var res = secp256k1_ecdsa_recoverable_signature_convert(context!, &signature, &recoverableSignature)
            if res != 1 { continue }
            
            var outputs = [UInt8](repeating: 0x00, count: 128)
            var outputlen = outputs.count
            
            // Serialize an ECDSA signature in DER format.
            res = secp256k1_ecdsa_signature_serialize_der(context!, &outputs, &outputlen, &signature)
            
            if res != 1 { continue }
            
            var resultData = Data(outputs)
            resultData.count = outputlen // 重新设置长度
            
            return resultData
        }
        return nil
    }
    
    /// 根据`hash`和`私钥`得到可恢复的签名（长度为65）
    public static func recoverableSignature(hash: Data?, privateKey: Data?, useExtraEntropy: Bool = true) -> Data? {
        guard let hash = hash else { return nil }
        guard let privateKey = privateKey else { return nil }
        guard hash.count == 32 else { return nil }
        guard privateKey.count == 32 else { return nil }
        // 验证私钥
        guard Crypto.SECP256K1.isValidPrivateKey(privateKey: privateKey) else { return nil }
        
        for _ in 0...1024 {
            // 得到签名数据
            guard let recoverableSignature: secp256k1_ecdsa_recoverable_signature = Crypto.SECP256K1._signForRecovery(hash: hash, privateKey: privateKey, useExtraEntropy: useExtraEntropy) else { continue }
            // 根据签名得到公钥数据
            guard let recoveredPublicKey: secp256k1_pubkey = Crypto.SECP256K1.recoverPublicKey(hash: hash, recoverableSignature: recoverableSignature) else {continue}
            // 根据私钥获取公钥数据
            guard let truePublicKey: secp256k1_pubkey = Crypto.SECP256K1.privateKeyToPublicKey(privateKey: privateKey) else { continue }
            
            // 这个方法不是很明白是做什么的，感觉是对两个公钥数据做比较？？
            guard Crypto.SECP256K1.constantTimeComparison(Data(toByteArray(truePublicKey.data)), Data(toByteArray(recoveredPublicKey.data))) else { continue }
            
            guard let serializedSignature = Crypto.SECP256K1.serializeSignature(recoverableSignature: recoverableSignature) else { continue }
            
            return serializedSignature
        }
        return nil
    }
    
    /// 根据私钥生成公钥
    public static func privateKeyToPublicKey(privateKey: Data?, compressed: Bool) -> Data? {
        // 得到公钥数据
        let publicKey = Crypto.SECP256K1.privateKeyToPublicKey(privateKey: privateKey)
        // 得到公钥
        return Crypto.SECP256K1.serializePublicKey(publicKey: publicKey, compressed: compressed)
    }
    
    
    /// 将多个公钥添加在一起并序列化（A+B）
    public static func combineSerializedPublicKeys(publicKeys: [Data], outputCompressed: Bool) -> Data? {
        guard publicKeys.count >= 1 else { return nil }
        
        var publicKey = secp256k1_pubkey()
        
        var storage = ContiguousArray<secp256k1_pubkey>()
        for key in publicKeys {
            guard let pubkey = Crypto.SECP256K1.parsePublicKey(publicKey: key) else { return nil }
            storage.append(pubkey)
        }
        
        let arrayOfPointers = UnsafeMutablePointer<UnsafePointer<secp256k1_pubkey>?>.allocate(capacity: publicKeys.count)
        defer {
            arrayOfPointers.deinitialize(count: publicKeys.count)
            arrayOfPointers.deallocate()
        }
        for i in 0 ..< publicKeys.count {
            withUnsafePointer(to: &storage[i]) { (ptr) -> Void in
                arrayOfPointers.advanced(by: i).pointee = ptr
            }
        }
        let immutablePointer = UnsafePointer(arrayOfPointers)
        
        // Add a number of public keys together.
        let result = secp256k1_ec_pubkey_combine(context!, &publicKey, immutablePointer, publicKeys.count)
        
        return result == 1 ? Crypto.SECP256K1.serializePublicKey(publicKey: publicKey, compressed: outputCompressed) : nil
    }
    
    /// 根据`hash`和`签名数据`拿到公钥
    public static func recoverPublicKey(hash: Data?, signature: Data?, compressed: Bool) -> Data? {
        guard let hash = hash else { return nil }
        guard let signature = signature else { return nil }
        guard hash.count == 32, signature.count == 65 else { return nil }
        // 获取签名数据
        guard let recoverableSignature = Crypto.SECP256K1.parseSignature(signature: signature) else { return nil }
        // 获取公钥数据
        guard let publicKey = Crypto.SECP256K1.recoverPublicKey(hash: hash, recoverableSignature: recoverableSignature) else { return nil }
        // 得到公钥
        guard let serializedKey = Crypto.SECP256K1.serializePublicKey(publicKey: publicKey, compressed: compressed) else { return nil }
        return serializedKey
    }
    
    /// 验证私钥
    public static func isValidPrivateKey(privateKey: Data?) -> Bool {
        guard let privateKey = privateKey else { return false }
        guard privateKey.count == 32 else { return false }
        var bytes = [UInt8](privateKey)
        // Verify an ECDSA secret key.
        let res = secp256k1_ec_seckey_verify(context!, &bytes)
        return res == 1
    }
    
    /// 随机生成一个私钥
    public static func generatePrivateKey() -> Data? {
        for _ in 0...1024 {
            guard let keyData = Crypto.randomData(length: 32) else { continue }
            guard Crypto.SECP256K1.isValidPrivateKey(privateKey: keyData) else { continue }
            return keyData
        }
        return nil
    }
    
    public static func unmarshalSignature(signatureData: Data?) -> UnmarshaledSignature? {
        guard let signatureData = signatureData else { return nil }
        guard signatureData.count == 65 else { return nil }
        let v = signatureData[64]
        let r = Data(signatureData[0..<32])
        let s = Data(signatureData[32..<64])
        return UnmarshaledSignature(v: v, r: r, s: s)
    }
    
    public static func marshalSignature(v: Data?, r: Data?, s: Data?) -> Data? {
        guard let v = v else { return nil }
        guard let r = r else { return nil }
        guard let s = s else { return nil }
        guard r.count == 32, s.count == 32 else { return nil }
        var completeSignature = Data(r)
        completeSignature.append(s)
        completeSignature.append(v)
        return completeSignature
    }
    
    public static func marshalSignature(v: UInt8, r: [UInt8], s: [UInt8]) -> Data? {
        return Crypto.SECP256K1.marshalSignature(v: Data([v]), r: Data(r), s: Data(s))
    }
    
    public static func constantTimeComparison(_ lhs: Data?, _ rhs:Data?) -> Bool {
        guard let lhs = lhs else { return false }
        guard let rhs = rhs else { return false }
        guard lhs.count == rhs.count else { return false }
        var difference = UInt8(0x00)
        for i in 0..<lhs.count { // compare full length
            difference |= lhs[i] ^ rhs[i] //constant time
        }
        return difference == UInt8(0x00)
    }
}

extension Crypto.SECP256K1 {
    /// 根据公钥`Data`解析为公钥数据
    private static func parsePublicKey(publicKey: Data?) -> secp256k1_pubkey? {
        guard let publicKey = publicKey else { return nil }
        guard publicKey.count == 33 || publicKey.count == 65 else { return nil }
        var publicKeyBytes = [UInt8](publicKey)
        
        let keyLen: Int = Int(publicKey.count)
        
        var pubkey = secp256k1_pubkey()
        
        // Parse a variable-length public key into the pubkey object.
        let res = secp256k1_ec_pubkey_parse(context!, &pubkey, &publicKeyBytes, keyLen)
        return res == 1 ? pubkey : nil
    }
    
    
    /// 序列化公钥数据，得到公钥
    private static func serializePublicKey(publicKey: secp256k1_pubkey?, compressed: Bool) -> Data? {
        guard var publicKey = publicKey else { return nil }
        var outputLength: Int = compressed ? 33 : 65
        let output = Data(repeating: 0x00, count: outputLength)
        let flags = UInt32(compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED)
        //
        var outputPtr = [UInt8](output)
        //
        let result = secp256k1_ec_pubkey_serialize(context!, &outputPtr, &outputLength, &publicKey, flags)
        return result == 1 ? Data(outputPtr) :  nil
    }
    
    /// 解析签名，得到签名数据
    private static func parseSignature(signature: Data?) -> secp256k1_ecdsa_recoverable_signature? {
        guard let signature = signature else { return nil }
        guard signature.count == 65 else { return nil }
        
        var recoverableSignature = secp256k1_ecdsa_recoverable_signature()
        
        var serializedSignatures = [UInt8](Data(signature[0..<64]))
        
        let recid = Int32(signature[64])
        
        // Parse a compact ECDSA signature (64 bytes + recovery id).
        let res = secp256k1_ecdsa_recoverable_signature_parse_compact(context!, &recoverableSignature, &serializedSignatures, recid)
        
        return res == 1 ? recoverableSignature : nil
    }
    
    /// 根据签名数据得到签名
    private static func serializeSignature(recoverableSignature: secp256k1_ecdsa_recoverable_signature?) -> Data? {
        guard var recoverableSignature = recoverableSignature else { return nil }
        var serializedSignature = [UInt8](Data(repeating: 0x00, count: 64))
        var recid: Int32 = 0
        
        // Serialize an ECDSA signature in compact format (64 bytes + recovery id).
        let res = secp256k1_ecdsa_recoverable_signature_serialize_compact(context!, &serializedSignature, &recid, &recoverableSignature)
        
        if res != 1 { return nil }
        
        serializedSignature.append(UInt8(recid))
        
        return Data(serializedSignature)
    }
    
    /// 根据`hash`和`签名数据`得到公钥数据
    private static func recoverPublicKey(hash: Data?, recoverableSignature: secp256k1_ecdsa_recoverable_signature?) -> secp256k1_pubkey? {
        guard let hash = hash else { return nil }
        guard var recoverableSignature = recoverableSignature else { return nil }
        guard hash.count == 32 else {return nil}
        var hashBytes = [UInt8](hash)
        
        var publicKey = secp256k1_pubkey()
        
        // Recover an ECDSA public key from a signature.
        let res = secp256k1_ecdsa_recover(context!, &publicKey, &recoverableSignature, &hashBytes)
        
        return res == 1 ? publicKey : nil
    }
    
    /// 根据私钥拿到公钥数据
    private static func privateKeyToPublicKey(privateKey: Data?) -> secp256k1_pubkey? {
        guard let privateKey = privateKey else { return nil }
        guard privateKey.count == 32 else { return nil }
        var publicKey = secp256k1_pubkey()
        var seckey = [UInt8](privateKey)
        
        // Compute the public key for a secret key.
        let result = secp256k1_ec_pubkey_create(context!, &publicKey, &seckey)
        
        return result == 1 ? publicKey : nil
    }
    
    /// 根据`hash`和`私钥`得到签名数据
    private static func _signForRecovery(hash: Data?, privateKey: Data?, useExtraEntropy: Bool) -> secp256k1_ecdsa_recoverable_signature? {
        guard let hash = hash else { return nil }
        guard let privateKey = privateKey else { return nil }
        guard hash.count == 32 || privateKey.count == 32 else { return nil }
        guard Crypto.SECP256K1.isValidPrivateKey(privateKey: privateKey) else { return nil }
        
        var hashBytes = [UInt8](hash)
        var privateKeyBytes = [UInt8](privateKey)
        
        var recoverableSignature = secp256k1_ecdsa_recoverable_signature()
        
        if useExtraEntropy {
            guard var extraEntropy = Crypto.randomData(length: 32) else { return nil }
            // Create a recoverable ECDSA signature.
            let result = secp256k1_ecdsa_sign_recoverable(context!, &recoverableSignature, &hashBytes, &privateKeyBytes, secp256k1_nonce_function_rfc6979, &extraEntropy)
            return result == 1 ? recoverableSignature : nil
        } else {
            // Create a recoverable ECDSA signature.
            let result = secp256k1_ecdsa_sign_recoverable(context!, &recoverableSignature, &hashBytes, &privateKeyBytes, secp256k1_nonce_function_rfc6979, nil)
            return result == 1 ? recoverableSignature : nil
        }
    }
    
    private static func toByteArray<T>(_ value: T) -> [UInt8] {
        var value = value
        return withUnsafeBytes(of: &value) { Array($0) }
    }
}
