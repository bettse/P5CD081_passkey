// wkfido: drive Apple's WebAuthn security-key stack from the command line.
//
// Safari, and Firefox on macOS, hand security-key requests to WebKit's
// AuthenticatorManager. _WKWebAuthenticationPanel is the private WebKit class
// that fronts it, and it runs in-process, so this tool exercises the same
// smart card discovery, APDU framing and CTAP2 code a browser does, with no
// browser and no UI.
//
//   wkfido create <rpId> [--rk] [--uv required|preferred|discouraged] [--algs -7,-257]
//   wkfido get <rpId> [--cred <hex>] [--uv ...]
//
// Environment: WKFIDO_PIN answers a PIN prompt, WKFIDO_TIMEOUT (seconds, default 25).
// Output: one JSON object on stdout. Exit 0 on success, 1 on error, 2 on timeout.
//
// Build: clang -fobjc-arc -framework Foundation -framework WebKit -framework CryptoTokenKit -o wkfido wkfido.m
//        codesign -f -s - --entitlements wkfido.entitlements wkfido

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <WebKit/WebKit.h>
#import <CryptoTokenKit/CryptoTokenKit.h>
#import <objc/runtime.h>

// ---- Private WebKit interfaces, declared from the open-source headers ----

@interface _WKPublicKeyCredentialEntity : NSObject
@property (nonatomic, copy) NSString *name;
@end
@interface _WKPublicKeyCredentialRelyingPartyEntity : _WKPublicKeyCredentialEntity
- (instancetype)initWithName:(NSString *)name;
@property (nullable, nonatomic, copy) NSString *identifier;
@end
@interface _WKPublicKeyCredentialUserEntity : _WKPublicKeyCredentialEntity
- (instancetype)initWithName:(NSString *)name identifier:(NSData *)identifier displayName:(NSString *)displayName;
@end
@interface _WKPublicKeyCredentialParameters : NSObject
- (instancetype)initWithAlgorithm:(NSNumber *)algorithm;
@end
@interface _WKPublicKeyCredentialDescriptor : NSObject
- (instancetype)initWithIdentifier:(NSData *)identifier;
@end
@interface _WKAuthenticatorSelectionCriteria : NSObject
@property (nonatomic) NSInteger authenticatorAttachment;   // 0 all, 1 platform, 2 cross-platform
@property (nonatomic) NSInteger residentKey;               // 0 absent, 1 required, 2 preferred, 3 discouraged
@property (nonatomic) BOOL requireResidentKey;
@property (nonatomic) NSInteger userVerification;          // 0 required, 1 preferred, 2 discouraged
@end
@interface _WKPublicKeyCredentialCreationOptions : NSObject
- (instancetype)initWithRelyingParty:(id)relyingParty user:(id)user publicKeyCredentialParamaters:(NSArray *)params;
@property (nullable, nonatomic, copy) NSNumber *timeout;
@property (nullable, nonatomic, strong) _WKAuthenticatorSelectionCriteria *authenticatorSelection;
@property (nonatomic) NSInteger attestation;
@end
@interface _WKPublicKeyCredentialRequestOptions : NSObject
@property (nullable, nonatomic, copy) NSNumber *timeout;
@property (nullable, nonatomic, copy) NSString *relyingPartyIdentifier;
@property (nullable, nonatomic, copy) NSArray *allowCredentials;
@property (nonatomic) NSInteger userVerification;
@property (nonatomic) NSInteger authenticatorAttachment;
@end
@interface _WKAuthenticatorResponse : NSObject
@property (nonatomic, strong, readonly) NSData *rawId;
@end
@interface _WKAuthenticatorAttestationResponse : _WKAuthenticatorResponse
@property (nonatomic, strong, readonly) NSData *attestationObject;
@end
@interface _WKAuthenticatorAssertionResponse : _WKAuthenticatorResponse
@property (nonatomic, readonly) NSData *authenticatorData;
@property (nonatomic, readonly) NSData *signature;
@property (nullable, nonatomic, readonly) NSData *userHandle;
@end
@class _WKWebAuthenticationPanel;
@protocol _WKWebAuthenticationPanelDelegate <NSObject>
@end
@interface _WKWebAuthenticationPanel : NSObject
@property (nullable, nonatomic, weak) id delegate;
- (void)makeCredentialWithClientDataHash:(NSData *)hash options:(id)options completionHandler:(void (^)(_WKAuthenticatorAttestationResponse *, NSError *))handler;
- (void)getAssertionWithClientDataHash:(NSData *)hash options:(id)options completionHandler:(void (^)(_WKAuthenticatorAssertionResponse *, NSError *))handler;
- (void)cancel;
@end

// ---- helpers ----

static NSString *hex(NSData *d)
{
    NSMutableString *s = [NSMutableString stringWithCapacity:d.length * 2];
    const uint8_t *b = d.bytes;
    for (NSUInteger i = 0; i < d.length; i++)
        [s appendFormat:@"%02x", b[i]];
    return s;
}

static NSData *unhex(NSString *s)
{
    NSMutableData *d = [NSMutableData data];
    for (NSUInteger i = 0; i + 1 < s.length; i += 2) {
        unsigned v = 0;
        [[NSScanner scannerWithString:[s substringWithRange:NSMakeRange(i, 2)]] scanHexInt:&v];
        uint8_t b = (uint8_t)v;
        [d appendBytes:&b length:1];
    }
    return d;
}

static void emit(NSDictionary *d, int code)
{
    NSData *json = [NSJSONSerialization dataWithJSONObject:d options:NSJSONWritingSortedKeys error:nil];
    printf("%s\n", [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding].UTF8String);
    fflush(stdout);
    exit(code);
}

static NSMutableArray *gEvents;

@interface Delegate : NSObject <_WKWebAuthenticationPanelDelegate>
@end

@implementation Delegate
- (void)panel:(id)panel updateWebAuthenticationPanel:(NSInteger)update
{
    NSArray *names = @[@"MultipleNFCTagsPresent", @"NoCredentialsFound", @"PINBlocked", @"PINAuthBlocked",
        @"PINInvalid", @"LAError", @"LAExcludeCredentialsMatched", @"LANoCredential", @"KeyStoreFull",
        @"PINTooShort", @"PINTooLong", @"PINSuccessful"];
    NSString *n = update >= 0 && update < (NSInteger)names.count ? names[update] : [NSString stringWithFormat:@"update %ld", (long)update];
    [gEvents addObject:n];
    fprintf(stderr, "panel update: %s\n", n.UTF8String);
}
- (void)panel:(id)panel requestPINWithRemainingRetries:(NSUInteger)retries completionHandler:(void (^)(NSString *))completionHandler
{
    const char *pin = getenv("WKFIDO_PIN");
    [gEvents addObject:[NSString stringWithFormat:@"PINRequested(retries=%lu)", (unsigned long)retries]];
    fprintf(stderr, "panel asked for a PIN (%lu retries left)%s\n", (unsigned long)retries, pin ? "" : ", none supplied");
    completionHandler(pin ? @(pin) : @"");
}
- (void)panel:(id)panel requestNewPINWithMinLength:(NSUInteger)minLength completionHandler:(void (^)(NSString *))completionHandler
{
    const char *pin = getenv("WKFIDO_PIN");
    [gEvents addObject:@"NewPINRequested"];
    fprintf(stderr, "panel asked to set a new PIN (min %lu)\n", (unsigned long)minLength);
    completionHandler(pin ? @(pin) : @"");
}
- (void)panel:(id)panel selectAssertionResponse:(NSArray *)responses source:(NSInteger)source completionHandler:(void (^)(id))completionHandler
{
    [gEvents addObject:[NSString stringWithFormat:@"SelectAssertion(%lu)", (unsigned long)responses.count]];
    completionHandler(responses.firstObject);
}
- (void)panel:(id)panel decidePolicyForLocalAuthenticatorWithCompletionHandler:(void (^)(NSInteger))completionHandler
{
    completionHandler(1); // disallow the Mac's own platform authenticator
}
- (void)panel:(id)panel dismissWebAuthenticationPanelWithResult:(NSInteger)result
{
    fprintf(stderr, "panel dismissed: %s\n", result == 0 ? "succeeded" : "failed");
}
@end

// WebKit's CcidService keeps one connection: the first slot that reports a
// valid card wins and no other slot is tried. With a SAM in the reader or a
// YubiKey plugged in, that is often not the card under test. WKFIDO_READER
// (substring match, default "CL Reader(1)") hides every other slot from
// WebKit so the run is repeatable. Set it to "*" to see WebKit's own choice.
static NSArray *(*gOrigSlotNames)(id, SEL);
static NSArray *filteredSlotNames(id self, SEL _cmd)
{
    NSArray<NSString *> *all = gOrigSlotNames(self, _cmd);
    const char *want = getenv("WKFIDO_READER");
    NSString *needle = want ? @(want) : @"CL Reader(1)";
    if ([needle isEqualToString:@"*"])
        return all;
    NSMutableArray *kept = [NSMutableArray array];
    for (NSString *n in all)
        if ([n containsString:needle])
            [kept addObject:n];
    return kept;
}

// APDU trace: wrap -[TKSmartCard transmitRequest:reply:] so every exchange
// WebKit has with the card is printed. The system log redacts these.
static void (*gOrigTransmit)(id, SEL, NSData *, void (^)(NSData *, NSError *));
static void tracedTransmit(id self, SEL _cmd, NSData *request, void (^reply)(NSData *, NSError *))
{
    fprintf(stderr, ">> %s\n", hex(request).UTF8String);
    gOrigTransmit(self, _cmd, request, ^(NSData *response, NSError *error) {
        if (error)
            fprintf(stderr, "<< error: %s\n", error.localizedDescription.UTF8String);
        else
            fprintf(stderr, "<< %s\n", hex(response).UTF8String);
        reply(response, error);
    });
}

static void installSlotFilter(void)
{
    if (!getenv("WKFIDO_QUIET")) {
        Method t = class_getInstanceMethod(NSClassFromString(@"TKSmartCard"), @selector(transmitRequest:reply:));
        if (t)
            gOrigTransmit = (void (*)(id, SEL, NSData *, void (^)(NSData *, NSError *)))method_setImplementation(t, (IMP)tracedTransmit);
    }
    Method m = class_getInstanceMethod(NSClassFromString(@"TKSmartCardSlotManager"), @selector(slotNames));
    if (!m) {
        fprintf(stderr, "could not find -[TKSmartCardSlotManager slotNames]\n");
        return;
    }
    gOrigSlotNames = (NSArray *(*)(id, SEL))method_setImplementation(m, (IMP)filteredSlotNames);
}

static NSInteger uvValue(NSString *s)
{
    if ([s isEqualToString:@"required"]) return 0;
    if ([s isEqualToString:@"discouraged"]) return 2;
    return 1;
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        NSArray<NSString *> *args = NSProcessInfo.processInfo.arguments;
        if (args.count < 3) {
            fprintf(stderr, "usage: wkfido create|get <rpId> [--rk] [--uv required|preferred|discouraged] [--algs -7,-257] [--cred hex]\n");
            return 64;
        }
        NSString *mode = args[1], *rpId = args[2];
        BOOL rk = NO;
        NSString *uv = @"preferred", *algs = @"-7,-257", *cred = nil;
        for (NSUInteger i = 3; i < args.count; i++) {
            if ([args[i] isEqualToString:@"--rk"]) rk = YES;
            else if ([args[i] isEqualToString:@"--uv"] && i + 1 < args.count) uv = args[++i];
            else if ([args[i] isEqualToString:@"--algs"] && i + 1 < args.count) algs = args[++i];
            else if ([args[i] isEqualToString:@"--cred"] && i + 1 < args.count) cred = args[++i];
        }

        gEvents = [NSMutableArray array];
        installSlotFilter();
        double timeout = getenv("WKFIDO_TIMEOUT") ? atof(getenv("WKFIDO_TIMEOUT")) : 25;

        uint8_t hashBytes[CC_SHA256_DIGEST_LENGTH];
        arc4random_buf(hashBytes, sizeof hashBytes);
        NSData *clientDataHash = [NSData dataWithBytes:hashBytes length:sizeof hashBytes];

        _WKWebAuthenticationPanel *panel = [[NSClassFromString(@"_WKWebAuthenticationPanel") alloc] init];
        if (!panel) {
            fprintf(stderr, "_WKWebAuthenticationPanel is not available in this WebKit\n");
            return 70;
        }
        Delegate *delegate = [Delegate new];
        panel.delegate = delegate;

        if ([mode isEqualToString:@"create"]) {
            _WKPublicKeyCredentialRelyingPartyEntity *rp = [[NSClassFromString(@"_WKPublicKeyCredentialRelyingPartyEntity") alloc] initWithName:rpId];
            rp.identifier = rpId;
            uint8_t uid[16];
            arc4random_buf(uid, sizeof uid);
            id user = [[NSClassFromString(@"_WKPublicKeyCredentialUserEntity") alloc] initWithName:@"probe@example" identifier:[NSData dataWithBytes:uid length:sizeof uid] displayName:@"Probe User"];
            NSMutableArray *params = [NSMutableArray array];
            for (NSString *a in [algs componentsSeparatedByString:@","])
                [params addObject:[[NSClassFromString(@"_WKPublicKeyCredentialParameters") alloc] initWithAlgorithm:@(a.integerValue)]];
            _WKPublicKeyCredentialCreationOptions *options = [[NSClassFromString(@"_WKPublicKeyCredentialCreationOptions") alloc] initWithRelyingParty:rp user:user publicKeyCredentialParamaters:params];
            _WKAuthenticatorSelectionCriteria *sel = [[NSClassFromString(@"_WKAuthenticatorSelectionCriteria") alloc] init];
            sel.authenticatorAttachment = 2;
            sel.userVerification = uvValue(uv);
            if (rk) {
                sel.residentKey = 1;
                sel.requireResidentKey = YES;
            }
            options.authenticatorSelection = sel;
            options.timeout = @(timeout * 1000);

            [panel makeCredentialWithClientDataHash:clientDataHash options:options completionHandler:^(_WKAuthenticatorAttestationResponse *resp, NSError *error) {
                if (error)
                    emit(@{ @"ok": @NO, @"error": error.localizedDescription ?: @"", @"code": @(error.code), @"events": gEvents }, 1);
                emit(@{ @"ok": @YES, @"clientDataHash": hex(clientDataHash), @"rawId": hex(resp.rawId),
                        @"attestationObject": hex(resp.attestationObject), @"events": gEvents }, 0);
            }];
        } else if ([mode isEqualToString:@"get"]) {
            _WKPublicKeyCredentialRequestOptions *options = [[NSClassFromString(@"_WKPublicKeyCredentialRequestOptions") alloc] init];
            options.relyingPartyIdentifier = rpId;
            options.userVerification = uvValue(uv);
            options.authenticatorAttachment = 2;
            options.timeout = @(timeout * 1000);
            if (cred)
                options.allowCredentials = @[[[NSClassFromString(@"_WKPublicKeyCredentialDescriptor") alloc] initWithIdentifier:unhex(cred)]];

            [panel getAssertionWithClientDataHash:clientDataHash options:options completionHandler:^(_WKAuthenticatorAssertionResponse *resp, NSError *error) {
                if (error)
                    emit(@{ @"ok": @NO, @"error": error.localizedDescription ?: @"", @"code": @(error.code), @"events": gEvents }, 1);
                emit(@{ @"ok": @YES, @"clientDataHash": hex(clientDataHash), @"rawId": hex(resp.rawId),
                        @"authenticatorData": hex(resp.authenticatorData), @"signature": hex(resp.signature),
                        @"userHandle": resp.userHandle ? hex(resp.userHandle) : @"", @"events": gEvents }, 0);
            }];
        } else {
            fprintf(stderr, "unknown mode %s\n", mode.UTF8String);
            return 64;
        }

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)((timeout + 2) * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [panel cancel];
            emit(@{ @"ok": @NO, @"error": @"timed out: no authenticator answered", @"events": gEvents }, 2);
        });
        [[NSRunLoop mainRunLoop] run];
    }
    return 0;
}
