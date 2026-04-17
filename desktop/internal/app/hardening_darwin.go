//go:build darwin

package app

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa -framework ApplicationServices -framework Carbon

#import <Cocoa/Cocoa.h>
#import <ApplicationServices/ApplicationServices.h>
#import <Carbon/Carbon.h>

extern void goOnSleep();
extern void goOnSessionResign();

static void registerSleepHook() {
    [[[NSWorkspace sharedWorkspace] notificationCenter]
        addObserverForName:NSWorkspaceWillSleepNotification
        object:nil
        queue:[NSOperationQueue mainQueue]
        usingBlock:^(NSNotification *note) {
            goOnSleep();
        }];
}

static void registerSessionResignHook() {
    [[[NSWorkspace sharedWorkspace] notificationCenter]
        addObserverForName:NSWorkspaceSessionDidResignActiveNotification
        object:nil
        queue:[NSOperationQueue mainQueue]
        usingBlock:^(NSNotification *note) {
            goOnSessionResign();
        }];
}

// --- Accessibility & Kiosk Mode ---

static int checkAccessibility() {
    return AXIsProcessTrusted();
}

static int promptAccessibility() {
    NSDictionary *options = @{
        (__bridge NSString *)kAXTrustedCheckOptionPrompt: @YES
    };
    return AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);
}

static void enterKioskMode() {
    @try {
        NSApplicationPresentationOptions opts =
            NSApplicationPresentationHideDock |
            NSApplicationPresentationHideMenuBar |
            NSApplicationPresentationDisableAppleMenu |
            NSApplicationPresentationDisableProcessSwitching |
            NSApplicationPresentationDisableForceQuit |
            NSApplicationPresentationDisableSessionTermination |
            NSApplicationPresentationDisableHideApplication |
            NSApplicationPresentationDisableMenuBarTransparency;

        [NSApp setPresentationOptions:opts];
    }
    @catch (NSException *exception) {
        NSLog(@"monban: failed to enter kiosk mode: %@", exception);
    }
}

static void exitKioskMode() {
    [NSApp setPresentationOptions:NSApplicationPresentationDefault];
}

// --- Dock visibility ---

static void showInDock() {
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
}

static void hideFromDock() {
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
}

// --- CGEventTap for keyboard shortcut blocking ---

#define kVK_Tab   0x30
#define kVK_Q     0x0C
#define kVK_W     0x0D
#define kVK_Space 0x31
#define kVK_Escape 0x35

static CFMachPortRef g_eventTap = NULL;

static CGEventRef kioskEventCallback(
    CGEventTapProxy proxy,
    CGEventType type,
    CGEventRef event,
    void *refcon
) {
    if (type == kCGEventTapDisabledByTimeout ||
        type == kCGEventTapDisabledByUserInput) {
        CGEventTapEnable(*(CFMachPortRef *)refcon, true);
        return event;
    }

    if (type != kCGEventKeyDown && type != kCGEventKeyUp) {
        return event;
    }

    CGEventFlags flags = CGEventGetFlags(event);
    CGKeyCode keyCode = (CGKeyCode)CGEventGetIntegerValueField(
        event, kCGKeyboardEventKeycode
    );

    int cmdDown  = (flags & kCGEventFlagMaskCommand) != 0;
    int optDown  = (flags & kCGEventFlagMaskAlternate) != 0;
    int ctrlDown = (flags & kCGEventFlagMaskControl) != 0;

    if (cmdDown) {
        switch (keyCode) {
            case kVK_Tab:
            case kVK_Q:
            case kVK_W:
            case kVK_Space:
                return NULL; // swallow
        }
    }

    // Block Cmd+Opt+Esc and Ctrl+Cmd+Esc (Force Quit variants)
    if (cmdDown && keyCode == kVK_Escape && (optDown || ctrlDown)) {
        return NULL;
    }

    return event;
}

static int startEventTap() {
    CGEventMask mask = CGEventMaskBit(kCGEventKeyDown) |
                       CGEventMaskBit(kCGEventKeyUp);

    g_eventTap = CGEventTapCreate(
        kCGHIDEventTap,
        kCGHeadInsertEventTap,
        kCGEventTapOptionDefault,
        mask,
        kioskEventCallback,
        &g_eventTap
    );

    if (!g_eventTap) {
        return -1;
    }

    CFRunLoopSourceRef src = CFMachPortCreateRunLoopSource(
        kCFAllocatorDefault, g_eventTap, 0
    );
    CFRunLoopAddSource(CFRunLoopGetMain(), src, kCFRunLoopCommonModes);
    CGEventTapEnable(g_eventTap, true);
    CFRelease(src);
    return 0;
}

static void stopEventTap() {
    if (g_eventTap) {
        CGEventTapEnable(g_eventTap, false);
        CFMachPortInvalidate(g_eventTap);
        CFRelease(g_eventTap);
        g_eventTap = NULL;
    }
}

*/
import "C"

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

var globalApp *App

func init() {
	exitKioskMode = darwinExitKioskMode
	enterKioskMode = darwinEnterKioskMode
	showInDock = darwinShowInDock
	hideFromDock = darwinHideFromDock
	hasAccessibilityPermission = darwinHasAccessibilityPermission
	promptAccessibilityPermission = darwinPromptAccessibilityPermission
}

func RegisterHardeningHooks(app *App) {
	globalApp = app

	C.registerSleepHook()
	C.registerSessionResignHook()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Println("monban: signal received, locking vaults...")
		_ = app.Lock()
		os.Exit(0)
	}()
}

func darwinHasAccessibilityPermission() bool {
	return C.checkAccessibility() != 0
}

func darwinPromptAccessibilityPermission() bool {
	return C.promptAccessibility() != 0
}

func darwinEnterKioskMode() {
	invokeSync(func() {
		log.Printf("monban: entering kiosk mode (accessibility=%v)", hasAccessibilityPermission())
		C.enterKioskMode()
		if C.startEventTap() != 0 {
			log.Println("monban: could not start event tap (accessibility not granted?)")
		} else {
			log.Println("monban: event tap started successfully")
		}
	})
}

func darwinExitKioskMode() {
	invokeSync(func() {
		C.stopEventTap()
		C.exitKioskMode()
	})
}

func darwinShowInDock() {
	invokeSync(func() {
		C.showInDock()
	})
}

func darwinHideFromDock() {
	invokeSync(func() {
		C.hideFromDock()
	})
}

//export goOnSleep
func goOnSleep() {
	if globalApp != nil {
		log.Println("monban: system sleep detected, locking vaults...")
		_ = globalApp.Lock()
	}
}

//export goOnSessionResign
func goOnSessionResign() {
	if globalApp != nil {
		log.Println("monban: session resign detected, locking vaults...")
		_ = globalApp.Lock()
	}
}
