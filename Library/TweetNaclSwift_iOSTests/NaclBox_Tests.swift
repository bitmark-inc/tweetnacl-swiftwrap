//
//  NaclBox_Tests.swift
//  NaclBox_Tests
//
//  Created by Anh Nguyen on 12/12/16.
//  Copyright © 2016 Bitmark. All rights reserved.
//

import XCTest
import TweetNaclSwift_iOS
@testable import TweetNaclSwift_iOS

class NaclBox_Test: XCTestCase {
    
    public var data: Array<String>?
    private let nonce = NSMutableData(length: crypto_box_NONCEBYTES)!
    
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testBox() {
        let pk = NaclUtil.decodeBase64(string: data![0])
        let sk = NaclUtil.decodeBase64(string: data![1])
        let msg = NaclUtil.decodeBase64(string: data![2])
        let goodBox = data![3]
        
        do {
            let box = try NaclBox.box(message: msg, nonce: nonce, publicKey: pk, secretKey: sk)
            let boxEncoded = NaclUtil.encodeBase64(data: box)
            
            XCTAssertEqual(boxEncoded, goodBox)
        }
        catch {
            XCTFail()
        }
    }
    
    override class func defaultTestSuite() -> XCTestSuite {
        
        let testSuite = XCTestSuite(name: NSStringFromClass(self))
        
        // A new test instance is created for each set of input + each test method
        // For example, there are 5 data sets and 2 test methods. This means
        // there will be 10 test case instances created and executed
        
        for array in boxTestData {
            addTestsWithArray(array: array, toTestSuite: testSuite)
        }
        
        return testSuite
    }
    
    private class func addTestsWithArray(array: [String], toTestSuite testSuite: XCTestSuite) {
        // Returns an array of NSInvocation, which are not available in Swift, but still seems to work.
        let invocations = self.testInvocations()
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
