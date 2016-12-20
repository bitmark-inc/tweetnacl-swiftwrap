//: Playground - noun: a place where people can play

import TweetNaclSwift_iOS

do {
    let keyPair = try NaclSign.KeyPair.keyPair()
    print(keyPair.publicKey)
    print(keyPair.secretKey)
}
catch (let e) {
    print(e)
}