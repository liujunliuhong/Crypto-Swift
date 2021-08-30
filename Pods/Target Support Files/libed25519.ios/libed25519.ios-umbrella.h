#ifdef __OBJC__
#import <UIKit/UIKit.h>
#else
#ifndef FOUNDATION_EXPORT
#if defined(__cplusplus)
#define FOUNDATION_EXPORT extern "C"
#else
#define FOUNDATION_EXPORT extern
#endif
#endif
#endif

#import "ed25519.h"

FOUNDATION_EXPORT double libed25519VersionNumber;
FOUNDATION_EXPORT const unsigned char libed25519VersionString[];

