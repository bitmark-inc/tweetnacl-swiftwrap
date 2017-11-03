//
//  NaclBox_Tests.swift
//  NaclBox_Tests
//
//  Created by Anh Nguyen on 12/12/16.
//  Copyright © 2016 Bitmark. All rights reserved.
//

import XCTest
@testable import TweetNacl

class NaclBox_Test: XCTestCase {
    
    public var data: Array<String>?
    private var nonce = Data(count: crypto_box_NONCEBYTES)
    
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testBox() {
        let pk = NaclUtil.decodeBase64(string: data![0])!
        let sk = NaclUtil.decodeBase64(string: data![1])!
        let msg = NaclUtil.decodeBase64(string: data![2])!
        let goodBox = data![3]
        
        do {
            let box = try NaclBox.box(message: msg, nonce: nonce, publicKey: pk, secretKey: sk)
            let boxEncoded = NaclUtil.encodeBase64(data: box)
            let open = try NaclBox.open(message: box, nonce: nonce, publicKey: pk, secretKey: sk)
            
            XCTAssertEqual(boxEncoded, goodBox)
            XCTAssertEqual(open, msg)
        }
        catch {
            XCTFail()
        }
    }
    
    override class var defaultTestSuite: XCTestSuite {
        
        let testSuite = XCTestSuite(name: NSStringFromClass(self))
        
        let testBundle = Bundle(for: NaclBox_Test.self)
        let fileURL = testBundle.url(forResource: "BoxTestData", withExtension: "json")
        let fileData = try! Data(contentsOf: fileURL!)
        let json = try! JSONSerialization.jsonObject(with: fileData, options: [])
        let arrayOfData = json as! [Array<String>]
        
        for array in arrayOfData {
            addTestsWithArray(array: array, toTestSuite: testSuite)
        }
        
        return testSuite
    }
    
    private class func addTestsWithArray(array: [String], toTestSuite testSuite: XCTestSuite) {
        // Returns an array of NSInvocation, which are not available in Swift, but still seems to work.
        let invocations = self.testInvocations
        for invocation in invocations {
            
            // We can't directly use the NSInvocation type in our source, but it appears
            // that we can pass it on through.
            let testCase = NaclBox_Test(invocation: invocation)
            
            // Normally the "parameterized" values are passed during initialization.
            // This is a "good enough" workaround. You'll see that I simply force unwrap
            // the optional at the callspot.
            testCase.data = array
            
            testSuite.addTest(testCase)
        }
    }
}
