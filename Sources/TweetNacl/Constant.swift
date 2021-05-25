//
//  Constant.swift
//  TweetnaclSwift
//
//  Created by Anh Nguyen on 12/9/16.
//  Copyright © 2016 Bitmark. All rights reserved.
//

struct Constants {
    struct Box {
        static let publicKeyBytes = 32
        static let secretKeyBytes = 32
        static let beforeNMBytes = 32
        static let nonceBytes = Secretbox.nonceBytes
        static let zeroBytes = Secretbox.zeroBytes
        static let boxZeroBytes = Secretbox.boxZeroBytes
    }

    struct Hash {
        static let bytes = 64
    }

    struct Scalarmult {
        static let bytes = 32
        static let scalarBytes = 32
    }

    struct Secretbox {
        static let keyBytes = 32
        static let nonceBytes = 24
        static let zeroBytes = 32
        static let boxZeroBytes = 16
    }

    struct Sign {
        static let bytes = 64
        static let publicKeyBytes = 32
        static let secretKeyBytes = 64
        static let seedBytes = 32
    }
}
