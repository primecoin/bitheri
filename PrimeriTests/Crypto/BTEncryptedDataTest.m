//
//  BTEncryptedDataTest.m
//  Primeri
//
//  Copyright 2014 http://Bither.net
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
#import <XCTest/XCTest.h>
#import "BTTestHelper.h"
#import "BTEncryptData.h"

@interface BTEncryptedDataTest : XCTestCase
@end

@implementation BTEncryptedDataTest {

}

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
    [BTTestHelper setup];
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testDealSaltFlag {
    NSString *encryptedString = @"ADF52483A2B1772A857FF4D3959C30CEB5DE9ECF86348864DB590A6DF000A10E/E6200101A89D8A769AF9B7111AA70A43/298BD8BCCBFAE7BA";
    NSString *encryptedString00 = @"ADF52483A2B1772A857FF4D3959C30CEB5DE9ECF86348864DB590A6DF000A10E/E6200101A89D8A769AF9B7111AA70A43/00298BD8BCCBFAE7BA";
    NSString *encryptedString01 = @"ADF52483A2B1772A857FF4D3959C30CEB5DE9ECF86348864DB590A6DF000A10E/E6200101A89D8A769AF9B7111AA70A43/01298BD8BCCBFAE7BA";
    NSString *encryptedString10 = @"ADF52483A2B1772A857FF4D3959C30CEB5DE9ECF86348864DB590A6DF000A10E/E6200101A89D8A769AF9B7111AA70A43/02298BD8BCCBFAE7BA";
    NSString *encryptedString11 = @"ADF52483A2B1772A857FF4D3959C30CEB5DE9ECF86348864DB590A6DF000A10E/E6200101A89D8A769AF9B7111AA70A43/03298BD8BCCBFAE7BA";

    XCTAssertTrue([encryptedString00 isEqualToString:[BTEncryptData encryptedString:encryptedString addIsCompressed:NO andIsXRandom:NO]]);
    XCTAssertTrue([encryptedString01 isEqualToString:[BTEncryptData encryptedString:encryptedString addIsCompressed:YES andIsXRandom:NO]]);
    XCTAssertTrue([encryptedString10 isEqualToString:[BTEncryptData encryptedString:encryptedString addIsCompressed:NO andIsXRandom:YES]]);
    XCTAssertTrue([encryptedString11 isEqualToString:[BTEncryptData encryptedString:encryptedString addIsCompressed:YES andIsXRandom:YES]]);

    XCTAssertTrue([encryptedString00 isEqualToString:[BTEncryptData encryptedString:encryptedString00 addIsCompressed:NO andIsXRandom:NO]]);
    XCTAssertTrue([encryptedString01 isEqualToString:[BTEncryptData encryptedString:encryptedString00 addIsCompressed:YES andIsXRandom:NO]]);
    XCTAssertTrue([encryptedString10 isEqualToString:[BTEncryptData encryptedString:encryptedString00 addIsCompressed:NO andIsXRandom:YES]]);
    XCTAssertTrue([encryptedString11 isEqualToString:[BTEncryptData encryptedString:encryptedString00 addIsCompressed:YES andIsXRandom:YES]]);

    XCTAssertTrue([encryptedString isEqualToString:[BTEncryptData encryptedStringRemoveFlag:encryptedString00]]);
    XCTAssertTrue([encryptedString isEqualToString:[BTEncryptData encryptedStringRemoveFlag:encryptedString01]]);
    XCTAssertTrue([encryptedString isEqualToString:[BTEncryptData encryptedStringRemoveFlag:encryptedString10]]);
    XCTAssertTrue([encryptedString isEqualToString:[BTEncryptData encryptedStringRemoveFlag:encryptedString11]]);
}

- (void)testNormal {
    NSString *encryptedString = @"146F830A2C15D92EF249FD0322C2C805BC3110DA766D7F5760D3B2D3B6C483224C6FF4591FBF6530FA8F75D5F84B16FB5932B516FEC29ED866756430A9C2F0E62C21BD5877F1D8679B214494183256E4/65FC320D854143EC94DA53EEA4BDA94B/3181134763EEA87A";
    NSData *data = [@"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" hexToData];
    BTEncryptData *encryptedData = [[BTEncryptData alloc] initWithStr:encryptedString];
    NSData *data1 = [encryptedData decrypt:@"111111"];
    XCTAssertTrue([data isEqualToData:[encryptedData decrypt:@"111111"]]);
}
@end
