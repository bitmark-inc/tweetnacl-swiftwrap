//
//  NSData+Extensions.swift
//  TweetnaclSwift
//
//  Created by Anh Nguyen on 12/12/16.
//  Copyright © 2016 Bitmark. All rights reserved.
//

import Foundation

public extension NSData {
    func bytesPtr<T>() -> UnsafePointer<T>{
        let rawBytes = self.bytes
        return rawBytes.assumingMemoryBound(to: T.self);
    }
}

public extension NSMutableData {
    func mutableBytesPtr<T>() -> UnsafeMutablePointer<T>{
        let rawBytes = self.mutableBytes
        return rawBytes.assumingMemoryBound(to: T.self)
    }
}
