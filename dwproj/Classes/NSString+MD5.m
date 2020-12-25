//
//  NSString+MD5.m
//  WealthCloud
//
//  Created by caifumap on 2017/3月/30.
//  Copyright © 2017年 caifumap. All rights reserved.
// MD5加密算法

#import "NSString+MD5.h"
#import <CommonCrypto/CommonDigest.h>

@implementation NSString (MD5)

#pragma mark - 32位 小写
+(NSString *)MD5ForLower32Bate:(NSString *)str{
    
    //要进行UTF8的转码
    const char* input = [str UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(input, (CC_LONG)strlen(input), result);
    
    NSMutableString *digest = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (NSInteger i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [digest appendFormat:@"%02x", result[i]];
    }
    
    return digest;
}

#pragma mark - 32位 大写
+(NSString *)MD5ForUpper32Bate:(NSString *)str{
    
    //要进行UTF8的转码
    const char* input = [str UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(input, (CC_LONG)strlen(input), result);
    
    NSMutableString *digest = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (NSInteger i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [digest appendFormat:@"%02X", result[i]];
    }
    
    return digest;
}

#pragma mark - 16位 大写
+(NSString *)MD5ForUpper16Bate:(NSString *)str{
    
    NSString *md5Str = [self MD5ForUpper32Bate:str];
    
    NSString *string;
    for (int i=0; i<24; i++) {
        string=[md5Str substringWithRange:NSMakeRange(8, 16)];
    }
    return string;
}


#pragma mark - 16位 小写
+(NSString *)MD5ForLower16Bate:(NSString *)str{
    
    NSString *md5Str = [self MD5ForLower32Bate:str];
    
    NSString *string;
    for (int i=0; i<24; i++) {
        string=[md5Str substringWithRange:NSMakeRange(8, 16)];
    }
    return string;
}


- (NSString *)rf_EncryptSHA1 {
    if (self.length<=0) return nil;

    const char *cstr = [self cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [NSData dataWithBytes:cstr length:self.length];

    return [NSString RF_EncryptSHA1:keyData];
}

+ (NSString *)RF_EncryptSHA1:(NSData *)keyData {
    if (keyData.length<=0) return nil;

    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(keyData.bytes, (unsigned int)keyData.length, digest);

    NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", digest[i]];
    }

    return output;
}

- (NSString *)rf_EncryptSHA256 {
    if (self.length<=0) return nil;

    const char *s = [self cStringUsingEncoding:NSASCIIStringEncoding];
    NSData *keyData = [NSData dataWithBytes:s length:strlen(s)];

    return [NSString RF_EncryptSHA256:keyData];
}

+ (NSString *)RF_EncryptSHA256:(NSData *)keyData {
    if (keyData.length<=0) return nil;

    uint8_t digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(keyData.bytes, (CC_LONG)keyData.length, digest);
    NSData *out = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    NSString *hash = [out description];
    hash = [hash stringByReplacingOccurrencesOfString:@" " withString:@""];
    hash = [hash stringByReplacingOccurrencesOfString:@"<" withString:@""];
    hash = [hash stringByReplacingOccurrencesOfString:@">" withString:@""];

    return hash;
}

- (NSString *)rf_EncryptMD5 {
    if (self.length<=0) return nil;

    const char *cStr = [self UTF8String];
    unsigned char digest[16];
    CC_MD5( cStr, (unsigned int)strlen(cStr), digest );

    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", digest[i]];
    }

    return  output;
}


@end
