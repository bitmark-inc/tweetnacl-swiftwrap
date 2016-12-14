//
//  Tweetnacl.swift
//  TweetnaclSwift
//
//  Created by Anh Nguyen on 12/9/16.
//  Copyright © 2016 Bitmark. All rights reserved.
//

import Foundation
import CTweetNacl

class NaclUtil {
    
    enum NaclUtilError: Error {
        case badKeySize
        case badNonceSize
        case badPublicKeySize
        case badSecretKeySize
        case internalError
    }
    
    static func checkLengths(key: NSData, nonce: NSData) throws {
        if key.length != crypto_secretbox_KEYBYTES {
            throw(NaclUtilError.badKeySize)
        }
        
        if nonce.length != crypto_secretbox_NONCEBYTES {
            throw NaclUtilError.badNonceSize
        }
    }
    
    static func checkBoxLength(publicKey: NSData, secretKey: NSData) throws {
        if publicKey.length != crypto_box_PUBLICKEYBYTES {
            throw(NaclUtilError.badPublicKeySize)
        }
        
        if secretKey.length != crypto_box_SECRETKEYBYTES {
            throw(NaclUtilError.badSecretKeySize)
        }
    }
    
    public static func randomBytes(_ length: Int) throws -> NSData {
        guard let data = NSMutableData(length: length) else {
            throw(NaclUtilError.internalError)
        }
        
        let result = SecRandomCopyBytes(kSecRandomDefault, data.length, data.mutableBytesPtr())
        
        if result != 0 {
            throw(NaclUtilError.internalError)
        }
        
        return data
    }
    
    public static func hash(message: NSData) throws -> NSData {
        guard let hash = NSMutableData(length: crypto_hash_BYTES) else {
            throw(NaclUtilError.internalError)
        }
        
        _ = CTweetNacl.crypto_hash_sha512_tweet(hash.mutableBytesPtr(), message.bytesPtr(), UInt64(message.length))
        
        return hash
    }
    
    public static func verify(x: NSData, y: NSData) throws -> Bool {
        if x.length == 0 || y.length == 0 {
            return false
        }
        
        if x.length != y.length {
            return false
        }
        
        let r = CTweetNacl.crypto_verify_32_tweet(x.bytesPtr(), y.bytesPtr())
        
        return r == 0
    }
    
    public static func encodeBase64(data: NSData) -> String {
        return data.base64EncodedString(options: [])
    }
    
    public static func decodeBase64(string: String) -> NSData {
        return NSData(base64Encoded: string, options: [])!
    }
}

fileprivate class NaclWrapper {
    enum NaclWrapperError: Error {
        case invalidParameters
        case internalError
        case creationFailed
    }
    
    fileprivate static func crypto_box_keypair(pk: inout NSMutableData, sk: inout NSMutableData) throws {
        let result = SecRandomCopyBytes(kSecRandomDefault, sk.length, sk.mutableBytesPtr())
        
        if result != 0 {
            throw(NaclWrapperError.creationFailed)
        }
        
        _ = CTweetNacl.crypto_scalarmult_curve25519_tweet_base(pk.mutableBytesPtr(), sk.bytesPtr())
    }
    
    fileprivate static func crypto_sign_keypair_wrap(pk: inout NSMutableData, sk: inout NSMutableData) throws {
        let result = SecRandomCopyBytes(kSecRandomDefault, sk.length, sk.mutableBytesPtr())
        
        if result != 0 {
            throw(NaclWrapperError.creationFailed)
        }
        
        _ = CTweetNacl.crypto_sign_ed25519_tweet_keypair(pk.mutableBytesPtr(), sk.mutableBytesPtr())
    }
    
    fileprivate static func crypto_sign_keypair_seeded(pk: inout NSMutableData, sk: inout NSMutableData) throws {
        _ = CTweetNacl.crypto_sign_ed25519_tweet_keypair(pk.mutableBytesPtr(), sk.mutableBytesPtr())
    }
}

public class NaclSecretBox {
    enum NaclSecretBoxError: Error {
        case invalidParameters
        case internalError
        case creationFailed
    }
    
    public static func secretBox(message: NSData, nonce: NSData, key: NSData) throws -> NSData {
        try NaclUtil.checkLengths(key: key, nonce: nonce)
        
        guard let m = NSMutableData(length: crypto_secretbox_ZEROBYTES + message.length) else {
            throw(NaclSecretBoxError.internalError)
        }
        
        guard let c = NSMutableData(length: m.length) else {
            throw(NaclSecretBoxError.internalError)
        }
        
        m.replaceBytes(in: NSMakeRange(crypto_secretbox_ZEROBYTES, message.length), withBytes: message.bytes)
        
        _ = CTweetNacl.crypto_secretbox_xsalsa20poly1305_tweet(c.mutableBytesPtr(), m.bytesPtr(), UInt64(m.length), nonce.bytesPtr(), key.bytesPtr())
        
        return NSData(data: c.subdata(with: NSMakeRange(crypto_secretbox_BOXZEROBYTES, c.length - crypto_secretbox_BOXZEROBYTES)))
    }
    
    public static func open(box: NSData, nonce: NSData, key: NSData) throws -> NSData {
        try NaclUtil.checkLengths(key: key, nonce: nonce)
        
        // Fill data
        var cValues = [UInt8](repeating:0, count:crypto_secretbox_BOXZEROBYTES + box.length)
        let boxByte = [UInt8](box as Data)
        for index in 0..<box.length {
            cValues[index + crypto_secretbox_BOXZEROBYTES] = boxByte[index]
        }
        
        let c = NSData(bytes: &cValues, length: crypto_secretbox_BOXZEROBYTES + box.length)
        
        guard let m = NSMutableData(length: c.length) else {
            throw(NaclSecretBoxError.internalError)
        }
        
        if c.length < 32 {
            throw(NaclSecretBoxError.creationFailed)
        }
        
        let r = CTweetNacl.crypto_secretbox_xsalsa20poly1305_tweet_open(m.mutableBytesPtr(), c.bytesPtr(), UInt64(c.length), nonce.bytesPtr(), key.bytesPtr())
        
        if r != 0 {
            throw(NaclSecretBoxError.creationFailed)
        }
        
        return NSData(data: m.subdata(with: NSMakeRange(crypto_secretbox_ZEROBYTES, c.length - crypto_secretbox_ZEROBYTES)))
    }
}

public class NaclScalarMult {
    enum NaclScalarMultError: Error {
        case invalidParameters
        case internalError
        case creationFailed
    }
    
    public static func scalarMult(n: NSData, p: NSData) throws -> NSData {
        if n.length != crypto_scalarmult_SCALARBYTES {
            throw(NaclScalarMultError.invalidParameters)
        }
        
        if p.length != crypto_scalarmult_BYTES {
            throw(NaclScalarMultError.invalidParameters)
        }
        
        guard let q = NSMutableData(length: crypto_scalarmult_BYTES) else {
            throw(NaclScalarMultError.internalError)
        }
        
        _ = CTweetNacl.crypto_scalarmult_curve25519_tweet(q.mutableBytesPtr(), n.bytesPtr(), p.bytesPtr())
        
        return q
    }
    
    public static func base(n: NSData) throws -> NSData {
        if n.length != crypto_scalarmult_SCALARBYTES {
            throw(NaclScalarMultError.invalidParameters)
        }
        
        guard let q = NSMutableData(length: crypto_scalarmult_BYTES) else {
            throw(NaclScalarMultError.internalError)
        }
        
        _ = CTweetNacl.crypto_scalarmult_curve25519_tweet_base(q.mutableBytesPtr(), n.bytesPtr())
        
        return q
    }
}

public class NaclBox {
    
    enum NaclBoxError: Error {
        case invalidParameters
        case internalError
        case creationFailed
    }
    
    public static func box(message: NSData, nonce: NSData, publicKey: NSData, secretKey: NSData) throws -> NSData {
        let key = try before(publicKey: publicKey, secretKey: secretKey)
        return try NaclSecretBox.secretBox(message: message, nonce: nonce, key: key)
    }
    
    public static func before(publicKey: NSData, secretKey: NSData) throws -> NSData {
        try NaclUtil.checkBoxLength(publicKey: publicKey, secretKey: secretKey)
        
        guard let k = NSMutableData(length: crypto_box_BEFORENMBYTES) else {
            throw(NaclBoxError.internalError)
        }
        
        _ = CTweetNacl.crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(k.mutableBytesPtr(), publicKey.bytesPtr(), secretKey.bytesPtr())
        
        return k
    }
    
    public static func open(message: NSData, nonce: NSData, publicKey: NSData, secretKey: NSData) throws -> NSData {
        let k = try before(publicKey: publicKey, secretKey: secretKey)
        return try NaclSecretBox.secretBox(message: message, nonce: nonce, key: k)
    }
    
    public static func keyPair() throws -> (publicKey: NSData, secretKey: NSData) {
        guard let pk = NSMutableData(length: crypto_box_PUBLICKEYBYTES) else {
            throw(NaclBoxError.internalError)
        }
        guard let sk = NSMutableData(length: crypto_box_SECRETKEYBYTES) else {
            throw(NaclBoxError.internalError)
        }
        
        let r = CTweetNacl.crypto_box_curve25519xsalsa20poly1305_tweet_keypair(pk.mutableBytesPtr(), sk.mutableBytesPtr())
        
        if r != 0 {
            throw(NaclBoxError.creationFailed)
        }
        
        return (pk, sk)
    }
    
    public static func keyPair(fromSecretKey secretKey: NSData) throws -> (publicKey: NSData, secretKey: NSData) {
        if secretKey.length != crypto_sign_SECRETKEYBYTES {
            throw(NaclBoxError.invalidParameters)
        }
        
        guard let pk = NSMutableData(length: crypto_box_PUBLICKEYBYTES) else {
            throw(NaclBoxError.internalError)
        }
        
        _ = CTweetNacl.crypto_scalarmult_curve25519_tweet_base(pk.mutableBytesPtr(), secretKey.bytesPtr())
        
        return (pk, secretKey)
    }
}

public class NaclSign {
    
    enum NaclSignError: Error {
        case invalidParameters
        case internalError
        case creationFailed
    }
    
    public static func sign(message: NSData, secretKey: NSData) throws -> NSData {
        if secretKey.length != crypto_sign_SECRETKEYBYTES {
            throw(NaclSignError.invalidParameters)
        }
        
        guard let signedMessage = NSMutableData(length: crypto_sign_BYTES + message.length) else {
            throw(NaclSignError.internalError)
        }
        
        let signedMessageLength = UnsafeMutablePointer<UInt64>.allocate(capacity: 1)
        _ = CTweetNacl.crypto_sign_ed25519_tweet(signedMessage.mutableBytesPtr(), signedMessageLength, message.bytesPtr(), UInt64(message.length), secretKey.bytesPtr())
        
        return signedMessage
    }
    
    public static func signOpen(signedMessage: NSData, publicKey: NSData) throws -> NSData {
        if publicKey.length != crypto_sign_PUBLICKEYBYTES {
            throw(NaclSignError.invalidParameters)
        }
        
        guard let tmp = NSMutableData(length: signedMessage.length) else {
            throw(NaclSignError.internalError)
        }
        
        let signedMessageLength = UnsafeMutablePointer<UInt64>.allocate(capacity: 1)
        
        let r = CTweetNacl.crypto_sign_ed25519_tweet_open(tmp.mutableBytesPtr(), signedMessageLength, signedMessage.bytesPtr(), UInt64(signedMessage.length), publicKey.bytesPtr())
        
        if r != 0 {
            throw(NaclSignError.creationFailed)
        }
        
        return tmp
    }
    
    public static func signDetached(message: NSData, secretKey: NSData) throws -> NSData {
        let signedMessage = try sign(message: message, secretKey: secretKey)
        
        let sig = signedMessage.subdata(with: NSMakeRange(0, crypto_sign_BYTES))
        
        return sig as NSData
    }
    
    public static func signDetachedVerify(message: NSData, sig: NSData, publicKey: NSData) throws -> Bool {
        if sig.length != crypto_sign_BYTES {
            throw(NaclSignError.invalidParameters)
        }
        
        if publicKey.length != crypto_sign_PUBLICKEYBYTES {
            throw(NaclSignError.invalidParameters)
        }
        
        let sm = NSMutableData()
        
        guard let m = NSMutableData(length: crypto_sign_BYTES + message.length) else {
            throw(NaclSignError.invalidParameters)
        }
        
        sm.append(sig as Data)
        sm.append(message as Data)
        
        let tmpLength = UnsafeMutablePointer<UInt64>.allocate(capacity: 1)
        
        let r =  CTweetNacl.crypto_sign_ed25519_tweet_open(m.mutableBytesPtr(), tmpLength, sm.bytesPtr(), UInt64(sm.length), publicKey.bytesPtr())
        
        return r == 0
    }
    
    public class KeyPair {
        public static func keyPair() throws -> (publicKey: NSData, secretKey: NSData) {
            guard var pk = NSMutableData(length: crypto_sign_PUBLICKEYBYTES) else {
                throw(NaclSignError.internalError)
            }
            
            guard var sk = NSMutableData(length: crypto_sign_SECRETKEYBYTES) else {
                throw(NaclSignError.internalError)
            }
            
            try NaclWrapper.crypto_sign_keypair_wrap(pk: &pk, sk: &sk)
        
            return (pk, sk)
        }
        
        public static func keyPair(fromSecretKey secretKey: NSData) throws -> (publicKey: NSData, secretKey: NSData) {
            if secretKey.length != crypto_sign_SECRETKEYBYTES {
                throw(NaclSignError.invalidParameters)
            }
            
            let data = secretKey.subdata(with: NSMakeRange(32, crypto_sign_PUBLICKEYBYTES))
            let pk = NSMutableData(data: data)
            
            return (pk, secretKey)
        }
        
        public static func keyPair(fromSeed seed: NSData) throws -> (publicKey: NSData, secretKey: NSData) {
            if seed.length != crypto_sign_SEEDBYTES {
                throw(NaclSignError.invalidParameters)
            }
            
            guard var pk = NSMutableData(length: crypto_sign_PUBLICKEYBYTES) else {
                throw(NaclSignError.internalError)
            }
            
            let seedPtr = seed.bytes
            var sk = NSMutableData(bytes: seedPtr, length: seed.length)
            
            try NaclWrapper.crypto_sign_keypair_seeded(pk: &pk, sk: &sk)
            
            return (pk, sk)
        }
    }
}
