package main

/*
#cgo darwin CFLAGS: -x objective-c
#cgo darwin LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

// haqSetWindowAlpha задаёт прозрачность всего окна (NSWindow.alphaValue).
// Выполняется на главной очереди — требование Cocoa для UI-операций.
static void haqSetWindowAlpha(void *win, double alpha) {
    if (win == NULL) return;
    NSWindow *w = (__bridge NSWindow *)win;
    dispatch_async(dispatch_get_main_queue(), ^{
        [w setAlphaValue:alpha];
    });
}
*/
import "C"

import "unsafe"

// setWindowAlpha устанавливает прозрачность нативного окна (0.4..1.0).
func setWindowAlpha(win unsafe.Pointer, alpha float64) {
	if win == nil {
		return
	}
	C.haqSetWindowAlpha(win, C.double(alpha))
}
