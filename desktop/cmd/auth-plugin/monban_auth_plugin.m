/*
 * monban_auth_plugin — macOS Authorization Plugin that delegates authentication
 * to the running Monban app via Unix socket IPC.
 *
 * SecurityAgent loads this plugin when authorization rights are configured to
 * use the "monban:auth" mechanism. The plugin connects to Monban's IPC socket,
 * sends an auth request, and waits for the app to perform FIDO2 assertion.
 *
 * Install: copy monban-auth.bundle to /Library/Security/SecurityAgentPlugins/
 * Configure: security authorizationdb write <right> ...
 */

#import <Foundation/Foundation.h>
#import <Security/AuthorizationPlugin.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <sys/socket.h>
#import <sys/un.h>
#import <pwd.h>
#import <unistd.h>

#define MONBAN_SOCKET_NAME "monban.sock"
#define MONBAN_IPC_TIMEOUT 60
#define MONBAN_CONNECT_TIMEOUT 5
#define MONBAN_RETRY_DELAY_US 500000 /* 500ms */

#pragma mark - Types

typedef struct {
    const AuthorizationCallbacks *callbacks;
} MonbanPlugin;

typedef struct {
    MonbanPlugin *plugin;
    AuthorizationEngineRef engine;
} MonbanMechanism;

#pragma mark - IPC

static NSString *monbanSocketPath(void) {
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    if (!pw) {
        /* Running as root in pluginhost — find the console user */
        SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("monban"), NULL, NULL);
        if (store) {
            uid_t consoleUID = 0;
            CFStringRef user = SCDynamicStoreCopyConsoleUser(store, &consoleUID, NULL);
            CFRelease(store);
            if (user) {
                CFRelease(user);
                pw = getpwuid(consoleUID);
            }
        }
    }
    if (!pw) return nil;
    return [NSString stringWithFormat:@"%s/.config/monban/%s", pw->pw_dir, MONBAN_SOCKET_NAME];
}

static int connectToSocket(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strlcpy(addr.sun_path, path, sizeof(addr.sun_path));

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int connectWithRetry(const char *path, int timeoutSec) {
    NSTimeInterval deadline = [NSDate timeIntervalSinceReferenceDate] + timeoutSec;

    while ([NSDate timeIntervalSinceReferenceDate] < deadline) {
        int fd = connectToSocket(path);
        if (fd >= 0) return fd;
        usleep(MONBAN_RETRY_DELAY_US);
    }
    return -1;
}

static BOOL launchMonban(void) {
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/usr/bin/open";
    task.arguments = @[@"-a", @"Monban"];
    @try {
        [task launch];
        return YES;
    } @catch (NSException *e) {
        return NO;
    }
}

static BOOL performIPCAuth(const char *socketPath, const char *service) {
    int fd = connectToSocket(socketPath);
    if (fd < 0) {
        /* App not running — try launching it */
        if (!launchMonban()) return NO;
        fd = connectWithRetry(socketPath, MONBAN_CONNECT_TIMEOUT);
        if (fd < 0) return NO;
    }

    /* Set read timeout */
    struct timeval tv = { .tv_sec = MONBAN_IPC_TIMEOUT, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Send JSON request */
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);

    /* For root pluginhost, resolve console user */
    const char *username = pw ? pw->pw_name : "unknown";
    if (uid == 0) {
        SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("monban"), NULL, NULL);
        if (store) {
            uid_t consoleUID = 0;
            CFStringRef user = SCDynamicStoreCopyConsoleUser(store, &consoleUID, NULL);
            CFRelease(store);
            if (user) {
                struct passwd *consolePw = getpwuid(consoleUID);
                if (consolePw) username = consolePw->pw_name;
                CFRelease(user);
            }
        }
    }

    NSString *json = [NSString stringWithFormat:
        @"{\"type\":\"auth\",\"user\":\"%s\",\"service\":\"%s\"}\n",
        username, service ? service : "authorization"];

    NSData *data = [json dataUsingEncoding:NSUTF8StringEncoding];
    ssize_t sent = write(fd, data.bytes, data.length);
    if (sent < 0) {
        close(fd);
        return NO;
    }

    /* Read JSON response */
    char buf[512] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n <= 0) return NO;

    NSData *respData = [NSData dataWithBytes:buf length:(NSUInteger)n];
    NSDictionary *resp = [NSJSONSerialization JSONObjectWithData:respData options:0 error:nil];
    if (!resp) return NO;

    return [resp[@"success"] boolValue];
}

#pragma mark - Plugin Interface

static OSStatus MonbanPluginDestroy(AuthorizationPluginRef inPlugin) {
    free(inPlugin);
    return errAuthorizationSuccess;
}

static OSStatus MonbanMechanismCreate(AuthorizationPluginRef inPlugin,
                                      AuthorizationEngineRef inEngine,
                                      AuthorizationMechanismId mechanismId,
                                      AuthorizationMechanismRef *outMechanism) {
    MonbanMechanism *mech = calloc(1, sizeof(MonbanMechanism));
    if (!mech) return errAuthorizationInternal;

    mech->plugin = (MonbanPlugin *)inPlugin;
    mech->engine = inEngine;
    *outMechanism = mech;
    return errAuthorizationSuccess;
}

static OSStatus MonbanMechanismInvoke(AuthorizationMechanismRef inMechanism) {
    MonbanMechanism *mech = (MonbanMechanism *)inMechanism;
    const AuthorizationCallbacks *cb = mech->plugin->callbacks;

    NSString *sockPath = monbanSocketPath();
    if (!sockPath) {
        cb->SetResult(mech->engine, kAuthorizationResultDeny);
        return errAuthorizationSuccess;
    }

    BOOL ok = performIPCAuth(sockPath.fileSystemRepresentation, "authorization");

    if (ok) {
        cb->SetResult(mech->engine, kAuthorizationResultAllow);
    } else {
        cb->SetResult(mech->engine, kAuthorizationResultDeny);
    }

    return errAuthorizationSuccess;
}

static OSStatus MonbanMechanismDeactivate(AuthorizationMechanismRef inMechanism) {
    MonbanMechanism *mech = (MonbanMechanism *)inMechanism;
    mech->plugin->callbacks->DidDeactivate(mech->engine);
    return errAuthorizationSuccess;
}

static OSStatus MonbanMechanismDestroy(AuthorizationMechanismRef inMechanism) {
    free(inMechanism);
    return errAuthorizationSuccess;
}

static AuthorizationPluginInterface sPluginInterface = {
    .version = kAuthorizationPluginInterfaceVersion,
    .PluginDestroy = MonbanPluginDestroy,
    .MechanismCreate = MonbanMechanismCreate,
    .MechanismInvoke = MonbanMechanismInvoke,
    .MechanismDeactivate = MonbanMechanismDeactivate,
    .MechanismDestroy = MonbanMechanismDestroy,
};

#pragma mark - Entry Point

OSStatus AuthorizationPluginCreate(const AuthorizationCallbacks *callbacks,
                                   AuthorizationPluginRef *outPlugin,
                                   const AuthorizationPluginInterface **outPluginInterface) {
    MonbanPlugin *plugin = calloc(1, sizeof(MonbanPlugin));
    if (!plugin) return errAuthorizationInternal;

    plugin->callbacks = callbacks;
    *outPlugin = plugin;
    *outPluginInterface = &sPluginInterface;

    return errAuthorizationSuccess;
}
