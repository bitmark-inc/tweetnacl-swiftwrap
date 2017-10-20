//
//  NaclScalarMulti_Tests.swift
//  TweetnaclSwift
//
//  Created by Anh Nguyen on 12/14/16.
//  Copyright © 2016 Bitmark. All rights reserved.
//

import XCTest
@testable import TweetNacl

class NaclScalarMulti_Tests: XCTestCase {
    public var data: Array<String>?
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
        
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
//    func testMultiBase() {
//        let testBytes : [UInt8] = [0x14, 0x00, 0xAB, 0x45, 0x49, 0x1F, 0xEF, 0x15,
//                                  0xA8, 0x89, 0x78, 0x0F, 0x09, 0xA9, 0x07, 0xB0,
//                                  0x01, 0x20, 0x01, 0x4E, 0x38, 0x32, 0x35, 0x56,
//                                  0x20, 0x20, 0x20, 0x00]
//        let golden = NSData(bytes: testBytes, length: testBytes.count)
//        
//        do {
//            let inputByte : [UInt8] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//                                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
//            var input = NSData(bytes: inputByte, length: inputByte.count)
//            
//            for _ in 0..<200 {
//                input = try NaclScalarMult.base(n: input)
//            }
//            
//            XCTAssertEqual(NaclUtil.encodeBase64(data: input), NaclUtil.encodeBase64(data: golden))
//        }
//        catch {
//            XCTFail()
//        }
//    }
    
    func testScalarMulti() {
        let pk1Dec = data![0]
        let pk1 = NaclUtil.decodeBase64(string: pk1Dec)!
        let sk1 = NaclUtil.decodeBase64(string: data![1])!
        let pk2Dec = data![2]
        let pk2 = NaclUtil.decodeBase64(string: pk2Dec)!
        let sk2 = NaclUtil.decodeBase64(string: data![3])!
        let out = data![4]
        
        do {
            let jpk1 = try NaclScalarMult.base(n: sk1)
            XCTAssertEqual(NaclUtil.encodeBase64(data: jpk1), pk1Dec)
            
            let jpk2 = try NaclScalarMult.base(n: sk2)
            XCTAssertEqual(NaclUtil.encodeBase64(data: jpk2), pk2Dec)
            
            let jout1 = try NaclScalarMult.scalarMult(n: sk1, p: pk2)
            XCTAssertEqual(NaclUtil.encodeBase64(data: jout1), out)
            
            let jout2 = try NaclScalarMult.scalarMult(n: sk2, p: pk1)
            XCTAssertEqual(NaclUtil.encodeBase64(data: jout2), out)
        }
        catch {
            XCTFail()
        }
    }
    
    override class var defaultTestSuite: XCTestSuite {
        
        let testSuite = XCTestSuite(name: NSStringFromClass(self))
        
        let testBundle = Bundle(for: NaclSecretbox_Tests.self)
        let fileURL = testBundle.url(forResource: "ScalarMultiTestData", withExtension: "json")
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
            let testCase = NaclScalarMulti_Tests(invocation: invocation)
            
            // Normally the "parameterized" values are passed during initialization.
            // This is a "good enough" workaround. You'll see that I simply force unwrap
            // the optional at the callspot.
            testCase.data = array
            
            testSuite.addTest(testCase)
        }
    }
    
}
