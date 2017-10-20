//
//  NaclSecretbox_Tests.swift
//  TweetnaclSwift
//
//  Created by Anh Nguyen on 12/14/16.
//  Copyright © 2016 Bitmark. All rights reserved.
//

import Foundation

import XCTest
@testable import TweetNacl

class NaclSecretbox_Tests: XCTestCase {
    
    public var data: [String]?
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testSecretBox() {
        let key = NaclUtil.decodeBase64(string: data![0])!
        let nonce = NaclUtil.decodeBase64(string: data![1])!
        let encodedMessage = data![2]
        let msg = NaclUtil.decodeBase64(string: encodedMessage)!
        let goodBox = data![3]
        
        do {
            let box = try NaclSecretBox.secretBox(message: msg, nonce: nonce, key: key)
            let boxEncoded = NaclUtil.encodeBase64(data: box)
            
            XCTAssertEqual(boxEncoded, goodBox)
            
            let openedBox = try NaclSecretBox.open(box: box, nonce: nonce, key: key)
            XCTAssertNotNil(openedBox)
            XCTAssertEqual(NaclUtil.encodeBase64(data: openedBox), encodedMessage)
        }
        catch {
            XCTFail()
        }
    }
    
    override class var defaultTestSuite: XCTestSuite {
        
        let testSuite = XCTestSuite(name: NSStringFromClass(self))
        
        let testBundle = Bundle(for: NaclSecretbox_Tests.self)
        let fileURL = testBundle.url(forResource: "SecretboxTestData", withExtension: "json")
        let fileData = try! Data(contentsOf: fileURL!)
        let jsonDecoder = JSONDecoder()
        let arrayOfData = try! jsonDecoder.decode([[String]].self, from: fileData)
        
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
            let testCase = NaclSecretbox_Tests(invocation: invocation)
            
            // Normally the "parameterized" values are passed during initialization.
            // This is a "good enough" workaround. You'll see that I simply force unwrap
            // the optional at the callspot.
            testCase.data = array
            
            testSuite.addTest(testCase)
        }
    }
}
