//
//  BTTestHelper.h
//  primeri
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

#import "BTTestHelper.h"


@implementation BTTestHelper {

}

+ (void)setup;{
    [[BTSettings instance] openPrimeriConsole];
    [[BTDatabaseManager instance] clear];
}

+ (NSArray *)readFile:(NSString *)fileName;{
    NSArray *myPathList = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *myPath = [myPathList objectAtIndex:0];
    myPath = [myPath stringByAppendingPathComponent:fileName];
    return  [[NSString stringWithContentsOfFile:myPath encoding:NSUTF8StringEncoding error:nil] componentsSeparatedByString:@"\n"];
}

+ (NSData *)readFileToData:(NSString *)fileName;{
    NSArray *myPathList = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *myPath = [myPathList objectAtIndex:0];
    myPath = [myPath stringByAppendingPathComponent:fileName];
    return [NSData dataWithContentsOfFile:myPath];
}
@end
