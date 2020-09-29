//
//  Tweetnacl.swift
//  TweetnaclSwift
//
//  Created by Anh Nguyen on 12/9/16.
//  Copyright © 2016 Bitmark. All rights reserved.
//

import Foundation
import CTweetNacl

struct NaclUtil {
    
    public enum NaclUtilError: Error {
        case badKeySize
        case badNonceSize
        case badPublicKeySize
        case badSecretKeySize
        case internalError
    }
    
    static func checkLengths(key: Data, nonce: Data) throws {
        if key.count != crypto_secretbox_KEYBYTES {
            throw(NaclUtilError.badKeySize)
        }
        
        if nonce.count != crypto_secretbox_NONCEBYTES {
            throw NaclUtilError.badNonceSize
        }
    }
    
    static func checkBoxLength(publicKey: Data, secretKey: Data) throws {
        if publicKey.count != crypto_box_PUBLICKEYBYTES {
            throw(NaclUtilError.badPublicKeySize)
        }
        
        if secretKey.count != crypto_box_SECRETKEYBYTES {
            throw(NaclUtilError.badSecretKeySize)
        }
    }
    
    public static func randomBytes(length: Int) throws -> Data {
        var data = Data(count: length)
        let result = try data.withUnsafeMutableBytes { pointer -> Int32 in
            guard let pointer = pointer.bindMemory(to: UInt8.self).baseAddress else {
                throw(NaclUtilError.internalError)
            }
            
            return SecRandomCopyBytes(kSecRandomDefault, length, pointer)
        }
        
        guard result == errSecSuccess else {
            throw(NaclUtilError.internalError)
        }
        
        return data
    }
    
    public static func hash(message: Data) throws -> Data {
        var hash = Data(count: crypto_hash_BYTES)
        let r = try hash.withUnsafeMutableBytes { hashPointer -> Int32 in
            return try message.withUnsafeBytes({ messagePointer -> Int32 in
                guard let hashPointer = hashPointer.bindMemory(to: UInt8.self).baseAddress,
                      let messagePointer = messagePointer.bindMemory(to: UInt8.self).baseAddress else {
                    throw(NaclUtilError.internalError)
                }
                
                return CTweetNacl.crypto_hash_sha512_tweet(hashPointer, messagePointer, UInt64(message.count))
            })
        }
        
        if r != 0 {
            throw(NaclUtilError.internalError)
        }
        
        return hash
    }
    
    public static func verify(x: Data, y: Data) throws -> Bool {
        if x.count == 0 || y.count == 0 {
            throw NaclUtilError.badKeySize
        }
        
        if x.count != y.count {
            throw NaclUtilError.badKeySize
        }
        
        let r = try x.withUnsafeBytes { xPointer -> Int32 in
            return try y.withUnsafeBytes({ yPointer -> Int32 in
                guard let xPointer = xPointer.bindMemory(to: UInt8.self).baseAddress,
                      let yPointer = yPointer.bindMemory(to: UInt8.self).baseAddress else {
                    throw(NaclUtilError.internalError)
                }
                
                return CTweetNacl.crypto_verify_32_tweet(xPointer, yPointer)
            })
        }
        
        return r == 0
    }
    
    public static func encodeBase64(data: Data) -> String {
        return data.base64EncodedString()
    }
    
    public static func decodeBase64(string: String) -> Data? {
        return Data(base64Encoded: string)
    }
}

fileprivate struct NaclWrapper {
    public enum NaclWrapperError: Error {
        case invalidParameters
        case internalError
        case creationFailed
    }
    
    fileprivate static func crypto_box_keypair(secretKey sk: Data) throws -> (publicKey: Data, secretKey: Data) {
        var pk = Data(count: crypto_box_SECRETKEYBYTES)
        
        let result = try pk.withUnsafeMutableBytes({ pkPointer -> Int32 in
            return try sk.withUnsafeBytes({ skPointer -> Int32 in
                guard let pkPointer = pkPointer.bindMemory(to: UInt8.self).baseAddress,
                      let skPointer = skPointer.bindMemory(to: UInt8.self).baseAddress else {
                    throw NaclWrapperError.internalError
                }
                
                return CTweetNacl.crypto_scalarmult_curve25519_tweet_base(pkPointer, skPointer)
            })
        })
        
        if result != 0 {
            throw NaclWrapperError.internalError
        }
        
        return (pk, sk)
    }
    
    fileprivate static func crypto_sign_keypair() throws -> (publicKey: Data, secretKey: Data) {
        let sk = try NaclUtil.randomBytes(length: crypto_sign_SECRETKEYBYTES)
        
        return try crypto_sign_keypair_seeded(secretKey: sk)
    }
    
    fileprivate static func crypto_sign_keypair_seeded(secretKey: Data) throws -> (publicKey: Data, secretKey: Data) {
        var pk = Data(count: crypto_sign_PUBLICKEYBYTES)
        var sk = Data(count: crypto_sign_SECRETKEYBYTES)
        sk.replaceSubrange(0..<crypto_sign_PUBLICKEYBYTES, with: secretKey.subdata(in: 0..<crypto_sign_PUBLICKEYBYTES))
        
        let result = try pk.withUnsafeMutableBytes({ pkPointer -> Int32 in
            return try sk.withUnsafeMutableBytes({ skPointer -> Int32 in
                guard let pkPointer = pkPointer.bindMemory(to: UInt8.self).baseAddress,
                      let skPointer = skPointer.bindMemory(to: UInt8.self).baseAddress else {
                    throw NaclWrapperError.internalError
                }
                
                return CTweetNacl.crypto_sign_ed25519_tweet_keypair(pkPointer, skPointer)
            })
        })
        
        if result != 0 {
            throw NaclWrapperError.internalError
        }
        
        return (pk, sk)
    }
}

public struct NaclSecretBox {
    public enum NaclSecretBoxError: Error {
        case invalidParameters
        case internalError
        case creationFailed
    }
    
    public static func secretBox(message: Data, nonce: Data, key: Data) throws -> Data {
        try NaclUtil.checkLengths(key: key, nonce: nonce)
        
        var m = Data(count: crypto_secretbox_ZEROBYTES + message.count)
        m.replaceSubrange(crypto_secretbox_ZEROBYTES..<m.count, with: message)
        
        var c = Data(count: m.count)
        
        let result = try c.withUnsafeMutableBytes { cPointer -> Int32 in
            return try m.withUnsafeBytes({ mPointer -> Int32 in
                return try nonce.withUnsafeBytes({ noncePointer -> Int32 in
                    return try key.withUnsafeBytes({ keyPointer -> Int32 in
                        guard let cPointer = cPointer.bindMemory(to: UInt8.self).baseAddress,
                              let mPointer = mPointer.bindMemory(to: UInt8.self).baseAddress,
                              let noncePointer = noncePointer.bindMemory(to: UInt8.self).baseAddress,
                              let keyPointer = keyPointer.bindMemory(to: UInt8.self).baseAddress else {
                            throw NaclSecretBoxError.internalError
                        }
                        
                        return CTweetNacl.crypto_secretbox_xsalsa20poly1305_tweet(cPointer, mPointer, UInt64(m.count), noncePointer, keyPointer)
                    })
                })
            })
        }
        
        if result != 0 {
            throw NaclSecretBoxError.internalError
        }
        return c.subdata(in: crypto_secretbox_BOXZEROBYTES..<c.count)
    }
    
    public static func open(box: Data, nonce: Data, key: Data) throws -> Data {
        try NaclUtil.checkLengths(key: key, nonce: nonce)
        
        // Fill data
        var c = Data(count: crypto_secretbox_BOXZEROBYTES + box.count)
        c.replaceSubrange(crypto_secretbox_BOXZEROBYTES..<c.count, with: box)
        
        var m = Data(count: c.count)
        
        let result = try m.withUnsafeMutableBytes { mPointer -> Int32 in
            return try c.withUnsafeBytes({ cPointer -> Int32 in
                return try nonce.withUnsafeBytes({ noncePointer -> Int32 in
                    return try key.withUnsafeBytes({ keyPointer -> Int32 in
                        guard let cPointer = cPointer.bindMemory(to: UInt8.self).baseAddress,
                              let mPointer = mPointer.bindMemory(to: UInt8.self).baseAddress,
                              let noncePointer = noncePointer.bindMemory(to: UInt8.self).baseAddress,
                              let keyPointer = keyPointer.bindMemory(to: UInt8.self).baseAddress else {
                            throw NaclSecretBoxError.internalError
                        }
                        
                        return CTweetNacl.crypto_secretbox_xsalsa20poly1305_tweet_open(mPointer, cPointer, UInt64(c.count), noncePointer, keyPointer)
                    })
                })
            })
        }
        
        if result != 0 {
            throw(NaclSecretBoxError.creationFailed)
        }
        
        return m.subdata(in: crypto_secretbox_ZEROBYTES..<c.count)
    }
}

public struct NaclScalarMult {
    public enum NaclScalarMultError: Error {
        case invalidParameters
        case internalError
        case creationFailed
    }
    
    public static func scalarMult(n: Data, p: Data) throws -> Data {
        if n.count != crypto_scalarmult_SCALARBYTES {
            throw(NaclScalarMultError.invalidParameters)
        }
        
        if p.count != crypto_scalarmult_BYTES {
            throw(NaclScalarMultError.invalidParameters)
        }
        
        var q = Data(count: crypto_scalarmult_BYTES)
        
        let result = try q.withUnsafeMutableBytes { qPointer -> Int32 in
            return try n.withUnsafeBytes({ nPointer -> Int32 in
                return try p.withUnsafeBytes({ pPointer -> Int32 in
                    guard let qPointer = qPointer.bindMemory(to: UInt8.self).baseAddress,
                          let nPointer = nPointer.bindMemory(to: UInt8.self).baseAddress,
                          let pPointer = pPointer.bindMemory(to: UInt8.self).baseAddress else {
                        throw NaclScalarMultError.internalError
                    }
                    
                    return CTweetNacl.crypto_scalarmult_curve25519_tweet(qPointer, nPointer, pPointer)
                })
            })
        }
        
        if result != 0 {
            throw(NaclScalarMultError.creationFailed)
        }
        
        return q
    }
    
    public static func base(n: Data) throws -> Data {
        if n.count != crypto_scalarmult_SCALARBYTES {
            throw(NaclScalarMultError.invalidParameters)
        }
        
        var q = Data(count: crypto_scalarmult_BYTES)
        
        let result = try q.withUnsafeMutableBytes { qPointer -> Int32 in
            return try n.withUnsafeBytes({ nPointer -> Int32 in
                guard let qPointer = qPointer.bindMemory(to: UInt8.self).baseAddress,
                      let nPointer = nPointer.bindMemory(to: UInt8.self).baseAddress else {
                    throw NaclScalarMultError.internalError
                }
                
                return CTweetNacl.crypto_scalarmult_curve25519_tweet_base(qPointer, nPointer)
            })
        }
        
        if result != 0 {
            throw(NaclScalarMultError.creationFailed)
        }
        
        return q
    }
}

public struct NaclBox {
    
    public enum NaclBoxError: Error {
        case invalidParameters
        case internalError
        case creationFailed
    }
    
    public static func box(message: Data, nonce: Data, publicKey: Data, secretKey: Data) throws -> Data {
        let key = try before(publicKey: publicKey, secretKey: secretKey)
        return try NaclSecretBox.secretBox(message: message, nonce: nonce, key: key)
    }
    
    public static func before(publicKey: Data, secretKey: Data) throws -> Data {
        try NaclUtil.checkBoxLength(publicKey: publicKey, secretKey: secretKey)
        
        var k = Data(count: crypto_box_BEFORENMBYTES)
        
        let result = try k.withUnsafeMutableBytes { kPointer -> Int32 in
            return try publicKey.withUnsafeBytes({ pkPointer -> Int32 in
                return try secretKey.withUnsafeBytes({ skPointer -> Int32 in
                    guard let kPointer = kPointer.bindMemory(to: UInt8.self).baseAddress,
                          let pkPointer = pkPointer.bindMemory(to: UInt8.self).baseAddress,
                          let skPointer = skPointer.bindMemory(to: UInt8.self).baseAddress else {
                        throw NaclBoxError.internalError
                    }
                    
                    return CTweetNacl.crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(kPointer, pkPointer, skPointer)
                })
            })
        }
        
        if result != 0 {
            throw(NaclBoxError.creationFailed)
        }
        
        return k
    }
    
    public static func open(message: Data, nonce: Data, publicKey: Data, secretKey: Data) throws -> Data {
        let k = try before(publicKey: publicKey, secretKey: secretKey)
        return try NaclSecretBox.open(box: message, nonce: nonce, key: k)
    }
    
    public static func keyPair() throws -> (publicKey: Data, secretKey: Data) {
        let sk = try NaclUtil.randomBytes(length: crypto_box_SECRETKEYBYTES)
        
        return try NaclWrapper.crypto_box_keypair(secretKey: sk)
    }
    
    public static func keyPair(fromSecretKey sk: Data) throws -> (publicKey: Data, secretKey: Data) {
        if sk.count != crypto_box_SECRETKEYBYTES {
            throw(NaclBoxError.invalidParameters)
        }
        
        return try NaclWrapper.crypto_box_keypair(secretKey: sk)
    }
}

public struct NaclSign {
    
    public enum NaclSignError: Error {
        case invalidParameters
        case internalError
        case creationFailed
    }
    
    public static func sign(message: Data, secretKey: Data) throws -> Data {
        if secretKey.count != crypto_sign_SECRETKEYBYTES {
            throw(NaclSignError.invalidParameters)
        }
        
        var signedMessage = Data(count: crypto_sign_BYTES + message.count)
        
        let tmpLength = UnsafeMutablePointer<UInt64>.allocate(capacity: 1)
        
        let result = try signedMessage.withUnsafeMutableBytes { signedMessagePointer -> Int32 in
            return try message.withUnsafeBytes({ messagePointer -> Int32 in
                return try secretKey.withUnsafeBytes({ secretKeyPointer -> Int32 in
                    guard let signedMessagePointer = signedMessagePointer.bindMemory(to: UInt8.self).baseAddress,
                          let messagePointer = messagePointer.bindMemory(to: UInt8.self).baseAddress,
                          let secretKeyPointer = secretKeyPointer.bindMemory(to: UInt8.self).baseAddress else {
                        throw NaclSignError.internalError
                    }
                    
                    return CTweetNacl.crypto_sign_ed25519_tweet(signedMessagePointer, tmpLength, messagePointer, UInt64(message.count), secretKeyPointer)
                })
            })
        }
        
        if result != 0 {
            throw NaclSignError.internalError
        }
        
        return signedMessage
    }
    
    public static func signOpen(signedMessage: Data, publicKey: Data) throws -> Data {
        if publicKey.count != crypto_sign_PUBLICKEYBYTES {
            throw(NaclSignError.invalidParameters)
        }
        
        var tmp = Data(count: signedMessage.count)
        let tmpLength = UnsafeMutablePointer<UInt64>.allocate(capacity: 1)
        
        let result = try tmp.withUnsafeMutableBytes { tmpPointer -> Int32 in
            return try signedMessage.withUnsafeBytes({ signMessagePointer -> Int32 in
                return try publicKey.withUnsafeBytes({ publicKeyPointer -> Int32 in
                    guard let tmpPointer = tmpPointer.bindMemory(to: UInt8.self).baseAddress,
                          let signMessagePointer = signMessagePointer.bindMemory(to: UInt8.self).baseAddress,
                          let publicKeyPointer = publicKeyPointer.bindMemory(to: UInt8.self).baseAddress else {
                        throw NaclSignError.internalError
                    }
                    
                    return CTweetNacl.crypto_sign_ed25519_tweet_open(tmpPointer, tmpLength, signMessagePointer, UInt64(signedMessage.count), publicKeyPointer)
                })
            })
        }
        
        if result != 0 {
            throw(NaclSignError.creationFailed)
        }
        
        return tmp
    }
    
    public static func signDetached(message: Data, secretKey: Data) throws -> Data {
        let signedMessage = try sign(message: message, secretKey: secretKey)
        
        let sig = signedMessage.subdata(in: 0..<crypto_sign_BYTES)
        
        return sig as Data
    }
    
    public static func signDetachedVerify(message: Data, sig: Data, publicKey: Data) throws -> Bool {
        if sig.count != crypto_sign_BYTES {
            throw(NaclSignError.invalidParameters)
        }
        
        if publicKey.count != crypto_sign_PUBLICKEYBYTES {
            throw(NaclSignError.invalidParameters)
        }
        
        var sm = Data()
        
        var m = Data(count: crypto_sign_BYTES + message.count)
        
        sm.append(sig )
        sm.append(message)
        
        let tmpLength = UnsafeMutablePointer<UInt64>.allocate(capacity: 1)
        
        let result = try m.withUnsafeMutableBytes { mPointer -> Int32 in
            return try sm.withUnsafeBytes({ smPointer -> Int32 in
                return try publicKey.withUnsafeBytes({ publicKeyPointer -> Int32 in
                    guard let mPointer = mPointer.bindMemory(to: UInt8.self).baseAddress,
                          let smPointer = smPointer.bindMemory(to: UInt8.self).baseAddress,
                          let publicKeyPointer = publicKeyPointer.bindMemory(to: UInt8.self).baseAddress else {
                        throw NaclSignError.internalError
                    }
                    
                    return CTweetNacl.crypto_sign_ed25519_tweet_open(mPointer, tmpLength, smPointer, UInt64(sm.count), publicKeyPointer)
                })
            })
        }
        
        return result == 0
    }
    
    public struct KeyPair {
        public static func keyPair() throws -> (publicKey: Data, secretKey: Data) {
            return try NaclWrapper.crypto_sign_keypair()
        }
        
        public static func keyPair(fromSecretKey secretKey: Data) throws -> (publicKey: Data, secretKey: Data) {
            if secretKey.count != crypto_sign_SECRETKEYBYTES {
                throw(NaclSignError.invalidParameters)
            }
            
            let pk = secretKey.subdata(in: crypto_sign_PUBLICKEYBYTES..<crypto_sign_SECRETKEYBYTES)
            
            return (pk, secretKey)
        }
        
        public static func keyPair(fromSeed seed: Data) throws -> (publicKey: Data, secretKey: Data) {
            if seed.count != 32 {
                throw(NaclSignError.invalidParameters)
            }
            
            return try NaclWrapper.crypto_sign_keypair_seeded(secretKey: seed)
        }
    }
}

