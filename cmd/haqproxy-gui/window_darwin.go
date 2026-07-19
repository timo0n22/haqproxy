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

// haqQuitOnClose завершает приложение при закрытии окна (красный крестик),
// иначе процесс остаётся висеть в фоне. Подписываемся на NSWindowWillCloseNotification.
static void haqQuitOnClose(void *win) {
    if (win == NULL) return;
    NSWindow *w = (__bridge NSWindow *)win;
    [[NSNotificationCenter defaultCenter]
        addObserverForName:NSWindowWillCloseNotification
                    object:w
                     queue:[NSOperationQueue mainQueue]
                usingBlock:^(NSNotification *note){
                    [NSApp terminate:nil];
                }];
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

// quitOnClose завершает приложение при закрытии окна (красный крестик).
func quitOnClose(win unsafe.Pointer) {
	if win == nil {
		return
	}
	C.haqQuitOnClose(win)
}
