//
//  ViewController.swift
//  TweetNaclSwift_Example
//
//  Created by Anh Nguyen on 12/12/16.
//  Copyright © 2016 Bitmark. All rights reserved.
//

import UIKit
import TweetNaclSwift_iOS

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        
        do {
            let keyPair = try NaclBox.keyPair()
            print(keyPair.secretKey)
            print(keyPair.publicKey)
        }
        catch (let e) {
            print(e)
        }
        
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

