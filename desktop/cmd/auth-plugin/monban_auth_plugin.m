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

#pragma mark - Auth cache
/*
 * Time-based auth cache. A single user-driven admin action (e.g. deleting a
 * user) can fan out into many separate authorization transactions — Apple's
 * writeconfig.xpc calls AuthorizationCopyRights repeatedly while performing
 * the underlying directory/file operations, each with a fresh engine ref.
 * Without caching the user would PIN+touch per transaction (we saw ~15 in
 * one delete flow), which is intolerable.
 *
 * After a successful FIDO2 auth we remember the time, username, and uid.
 * Subsequent mechanism invocations within AUTH_CACHE_TTL_SECONDS replay the
 * cached result immediately. This mirrors Apple's built-in `shared: true`
 * behavior for password rights.
 *
 * Security tradeoff: any admin auth request during the cache window proceeds
 * without a fresh YubiKey tap. This is equivalent to how sudo caches the
 * user's password for a few minutes after a successful entry.
 */
#define AUTH_CACHE_TTL_SECONDS 60.0
// Denial cache is shorter — we want the user to be able to retry soon, but
// not be prompted 15 more times in the same authd transaction after saying
// "cancel" once.
#define DENY_CACHE_TTL_SECONDS 10.0

static dispatch_queue_t sCacheQueue;
static NSDate *sCachedAt;
static char sCachedUsername[256];
static uid_t sCachedUID;
static NSDate *sDeniedAt;

static void cacheInit(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        sCacheQueue = dispatch_queue_create("com.monban.authplugin.cache", DISPATCH_QUEUE_SERIAL);
    });
}

static BOOL cacheLookup(char *usernameOut, size_t usernameCap, uid_t *uidOut) {
    cacheInit();
    __block BOOL hit = NO;
    dispatch_sync(sCacheQueue, ^{
        if (sCachedAt == nil) return;
        if ([[NSDate date] timeIntervalSinceDate:sCachedAt] > AUTH_CACHE_TTL_SECONDS) return;
        strlcpy(usernameOut, sCachedUsername, usernameCap);
        *uidOut = sCachedUID;
        hit = YES;
    });
    return hit;
}

static void cacheStore(const char *username, uid_t uid) {
    cacheInit();
    dispatch_sync(sCacheQueue, ^{
        sCachedAt = [NSDate date];
        strlcpy(sCachedUsername, username, sizeof(sCachedUsername));
        sCachedUID = uid;
    });
    // A successful auth implicitly clears any pending denial.
    dispatch_sync(sCacheQueue, ^{
        sDeniedAt = nil;
    });
}

static BOOL denyCacheHit(void) {
    cacheInit();
    __block BOOL hit = NO;
    dispatch_sync(sCacheQueue, ^{
        if (sDeniedAt == nil) return;
        if ([[NSDate date] timeIntervalSinceDate:sDeniedAt] > DENY_CACHE_TTL_SECONDS) return;
        hit = YES;
    });
    return hit;
}

static void denyCacheStore(void) {
    cacheInit();
    dispatch_sync(sCacheQueue, ^{
        sDeniedAt = [NSDate date];
    });
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

/*
 * Resolve the console-owning username + uid. When SecurityAgent runs our
 * mechanism, the plugin host is typically uid 92 (securityagent) or 0
 * (root), NOT the user being authorized — so we can't just use getuid().
 * We ask SystemConfiguration for the current console user, matching what
 * builtin mechanisms do.
 */
static BOOL resolveConsoleUser(char *usernameOut, size_t usernameCap, uid_t *uidOut) {
    SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("monban"), NULL, NULL);
    if (!store) return NO;
    uid_t consoleUID = 0;
    CFStringRef user = SCDynamicStoreCopyConsoleUser(store, &consoleUID, NULL);
    CFRelease(store);
    if (!user) return NO;
    BOOL ok = NO;
    if (CFStringGetCString(user, usernameOut, (CFIndex)usernameCap, kCFStringEncodingUTF8)) {
        *uidOut = consoleUID;
        ok = YES;
    }
    CFRelease(user);
    return ok;
}

static void setAuthContext(const AuthorizationCallbacks *cb,
                           AuthorizationEngineRef engine,
                           const char *username, uid_t uid) {
    AuthorizationValue userVal = {
        .length = strlen(username),
        .data = (void *)username,
    };
    cb->SetContextValue(engine, "username",
                        kAuthorizationContextFlagExtractable, &userVal);

    AuthorizationValue uidVal = {
        .length = sizeof(uid),
        .data = &uid,
    };
    cb->SetContextValue(engine, "uid",
                        kAuthorizationContextFlagExtractable, &uidVal);
}

static OSStatus MonbanMechanismInvoke(AuthorizationMechanismRef inMechanism) {
    MonbanMechanism *mech = (MonbanMechanism *)inMechanism;
    const AuthorizationCallbacks *cb = mech->plugin->callbacks;

    /*
     * Denial cache hit: the user recently cancelled an auth (or it failed
     * out). authd may still fan the same transaction into multiple rights
     * or subsequent admin operations; suppressing them keeps us from
     * re-prompting. Checked BEFORE the success cache so a fresh denial
     * always takes priority.
     */
    if (denyCacheHit()) {
        cb->SetResult(mech->engine, kAuthorizationResultDeny);
        return errAuthorizationSuccess;
    }

    /*
     * Time-based cache hit: within AUTH_CACHE_TTL_SECONDS of the last
     * successful FIDO2 auth, skip re-prompting. Matches sudo's password
     * caching behavior and handles the case where one user-facing action
     * (e.g. delete user) fans out into many separate authorization
     * transactions under the hood.
     */
    char cachedUsername[256] = {0};
    uid_t cachedUID = 0;
    if (cacheLookup(cachedUsername, sizeof(cachedUsername), &cachedUID)) {
        setAuthContext(cb, mech->engine, cachedUsername, cachedUID);
        cb->SetResult(mech->engine, kAuthorizationResultAllow);
        return errAuthorizationSuccess;
    }

    NSString *sockPath = monbanSocketPath();
    if (!sockPath) {
        cb->SetResult(mech->engine, kAuthorizationResultDeny);
        return errAuthorizationSuccess;
    }

    BOOL ok = performIPCAuth(sockPath.fileSystemRepresentation, "authorization");

    if (ok) {
        /*
         * SecurityAgent won't accept a bare "Allow" — it needs the
         * authenticating user's uid + username in the authorization
         * context, otherwise downstream callers (Users & Groups, etc.)
         * get "Mechanism did not return a uid" and fall back to the
         * password prompt. Must be set BEFORE SetResult.
         */
        char username[256] = {0};
        uid_t uid = 0;
        if (resolveConsoleUser(username, sizeof(username), &uid)) {
            setAuthContext(cb, mech->engine, username, uid);
            cacheStore(username, uid);
        }
        cb->SetResult(mech->engine, kAuthorizationResultAllow);
    } else {
        // Remember the denial briefly so authd doesn't re-invoke us for
        // every subsequent right in the same multi-right transaction (or
        // related admin op). Short TTL lets the user retry fresh shortly.
        denyCacheStore();
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
