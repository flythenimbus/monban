/*
 * monban_auth_plugin — macOS Authorization Plugin bundle.
 *
 * Loaded by the macOS SecurityAgent process when authorizationdb rights
 * (see installer/gated-rights.sh) are rebound to the monban-auth:auth
 * mechanism. The bundle proxies the auth decision to the admin-gate
 * plugin running inside Monban via the Unix socket at
 *
 *     ~/.config/monban/plugins/admin-gate/helper.sock
 *
 * which in turn relays to Monban's UI via the request_pin_touch RPC.
 * On success, the bundle tells SecurityAgent to allow the right;
 * otherwise it denies (and the stack falls through to Apple's default
 * password prompt).
 *
 * Install: copy monban-auth.bundle into /Library/Security/SecurityAgentPlugins/.
 * The installer also rebinds GATED_RIGHTS via `security authorizationdb`
 * to point at the monban-auth:auth mechanism.
 */

#import <Foundation/Foundation.h>
#import <Security/AuthorizationPlugin.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <sys/socket.h>
#import <sys/un.h>
#import <pwd.h>
#import <unistd.h>

#define MONBAN_SOCKET_NAME "helper.sock"
#define MONBAN_PLUGIN_REL  ".config/monban/plugins/admin-gate/" MONBAN_SOCKET_NAME
#define MONBAN_IPC_TIMEOUT 180
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

#pragma mark - Console-user lookup

/*
 * Resolve the console-owning user. SecurityAgent runs our mechanism as
 * uid 92 (securityagent) or 0 (root), not the user whose admin action
 * triggered the prompt — we can't use getuid() for the socket path or
 * for the authorization context value.
 */
static BOOL resolveConsoleUser(char *usernameOut, size_t usernameCap,
                               uid_t *uidOut, char *homeOut, size_t homeCap) {
    SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("monban"), NULL, NULL);
    if (!store) return NO;
    uid_t consoleUID = 0;
    CFStringRef user = SCDynamicStoreCopyConsoleUser(store, &consoleUID, NULL);
    CFRelease(store);
    if (!user) return NO;

    BOOL ok = NO;
    if (CFStringGetCString(user, usernameOut, (CFIndex)usernameCap, kCFStringEncodingUTF8)) {
        *uidOut = consoleUID;
        struct passwd *pw = getpwuid(consoleUID);
        if (pw && homeOut) {
            strlcpy(homeOut, pw->pw_dir, homeCap);
        }
        ok = YES;
    }
    CFRelease(user);
    return ok;
}

#pragma mark - IPC

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

/*
 * performIPCAuth sends {"user","service"} to admin-gate's socket and
 * waits for {"ok":bool}. On success (ok=true) returns YES. If the
 * socket doesn't exist (Monban not running), launches Monban first
 * and retries with a short timeout.
 */
static BOOL performIPCAuth(const char *socketPath, const char *username, const char *service) {
    int fd = connectToSocket(socketPath);
    if (fd < 0) {
        if (!launchMonban()) return NO;
        fd = connectWithRetry(socketPath, MONBAN_CONNECT_TIMEOUT);
        if (fd < 0) return NO;
    }

    struct timeval tv = { .tv_sec = MONBAN_IPC_TIMEOUT, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* H4: build request with NSJSONSerialization so any future change
     * that feeds user-controlled strings through this path can't
     * produce a malformed / injectable payload. */
    NSDictionary *payload = @{
        @"user":    [NSString stringWithUTF8String:username ?: ""],
        @"service": [NSString stringWithUTF8String:service ?: "authorization"],
    };
    NSError *jerr = nil;
    NSData *body = [NSJSONSerialization dataWithJSONObject:payload options:0 error:&jerr];
    if (!body || jerr) {
        close(fd);
        return NO;
    }
    NSMutableData *framed = [NSMutableData dataWithData:body];
    [framed appendBytes:"\n" length:1];
    ssize_t sent = write(fd, framed.bytes, framed.length);
    if (sent < 0) {
        close(fd);
        return NO;
    }

    char buf[512] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return NO;

    NSData *respData = [NSData dataWithBytes:buf length:(NSUInteger)n];
    NSDictionary *resp = [NSJSONSerialization JSONObjectWithData:respData options:0 error:nil];
    if (!resp) return NO;
    return [resp[@"ok"] boolValue];
}

#pragma mark - Auth cache
/*
 * Time-based auth cache. A single user-driven admin action (deleting a
 * user, changing a panel, etc.) can fan out into many separate
 * AuthorizationCopyRights transactions — authd invokes us per right
 * with a fresh engine. Without caching the user would PIN+touch per
 * transaction (~15× for a single delete-user flow), which is
 * intolerable. On a successful FIDO2 auth we remember the time +
 * user; subsequent mechanism invocations within AUTH_CACHE_TTL_SECONDS
 * replay the cached result immediately. Mirrors Apple's built-in
 * `shared: true` behaviour for password rights.
 *
 * Denial cache (shorter TTL) prevents re-prompting after a cancel.
 */
#define AUTH_CACHE_TTL_SECONDS 60.0
#define DENY_CACHE_TTL_SECONDS 10.0

static dispatch_queue_t sCacheQueue;
static NSDate *sCachedAt;
static char sCachedUsername[256];
static uid_t sCachedUID;
/*
 * N4: denial cache must key on (uid, username) the same way the
 * success cache does, otherwise user A cancelling a prompt briefly
 * blocks user B's admin actions on a multi-session Mac.
 */
static NSDate *sDeniedAt;
static uid_t sDeniedUID;
static char sDeniedUsername[256];

static void cacheInit(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        sCacheQueue = dispatch_queue_create("com.monban.authplugin.cache", DISPATCH_QUEUE_SERIAL);
    });
}

/*
 * cacheLookup only hits when the cached entry matches the *current*
 * console user. C3: the cache was previously time-only, which meant
 * user A's success within 60 s would satisfy a right triggered by
 * user B (fast user switching, multi-session). Now the caller resolves
 * the live console user first and passes (uid, username); a cached
 * entry from a different session is a miss.
 */
static BOOL cacheLookup(uid_t wantUID, const char *wantUsername) {
    cacheInit();
    __block BOOL hit = NO;
    dispatch_sync(sCacheQueue, ^{
        if (sCachedAt == nil) return;
        if ([[NSDate date] timeIntervalSinceDate:sCachedAt] > AUTH_CACHE_TTL_SECONDS) return;
        if (sCachedUID != wantUID) return;
        if (strncmp(sCachedUsername, wantUsername, sizeof(sCachedUsername)) != 0) return;
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
        sDeniedAt = nil;
    });
}

static BOOL denyCacheHit(uid_t wantUID, const char *wantUsername) {
    cacheInit();
    __block BOOL hit = NO;
    dispatch_sync(sCacheQueue, ^{
        if (sDeniedAt == nil) return;
        if ([[NSDate date] timeIntervalSinceDate:sDeniedAt] > DENY_CACHE_TTL_SECONDS) return;
        if (sDeniedUID != wantUID) return;
        if (strncmp(sDeniedUsername, wantUsername, sizeof(sDeniedUsername)) != 0) return;
        hit = YES;
    });
    return hit;
}

static void denyCacheStore(uid_t uid, const char *username) {
    cacheInit();
    dispatch_sync(sCacheQueue, ^{
        sDeniedAt = [NSDate date];
        sDeniedUID = uid;
        strlcpy(sDeniedUsername, username, sizeof(sDeniedUsername));
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
     * C3 + N4: resolve console user BEFORE any cache lookup so both
     * success AND denial caches can be keyed to this session. If the
     * console user flipped (fast user switching, multi-session), we
     * must not let user A's state bleed into user B's auth.
     */
    char username[256] = {0};
    uid_t uid = 0;
    char home[1024] = {0};
    if (!resolveConsoleUser(username, sizeof(username), &uid, home, sizeof(home))) {
        cb->SetResult(mech->engine, kAuthorizationResultDeny);
        return errAuthorizationSuccess;
    }

    /* Fresh denial for THIS session wins — prevents multi-right re-prompting after cancel. */
    if (denyCacheHit(uid, username)) {
        cb->SetResult(mech->engine, kAuthorizationResultDeny);
        return errAuthorizationSuccess;
    }

    /* Recent-success cache: same admin action, multiple authd calls, same session. */
    if (cacheLookup(uid, username)) {
        setAuthContext(cb, mech->engine, username, uid);
        cb->SetResult(mech->engine, kAuthorizationResultAllow);
        return errAuthorizationSuccess;
    }

    char sockPath[2048] = {0};
    snprintf(sockPath, sizeof(sockPath), "%s/%s", home, MONBAN_PLUGIN_REL);

    BOOL ok = performIPCAuth(sockPath, username, "authorization");

    if (ok) {
        /*
         * SecurityAgent requires the uid + username in the context or
         * downstream callers get "Mechanism did not return a uid" and
         * fall back to the password prompt. Must be set BEFORE SetResult.
         */
        setAuthContext(cb, mech->engine, username, uid);
        cacheStore(username, uid);
        cb->SetResult(mech->engine, kAuthorizationResultAllow);
    } else {
        denyCacheStore(uid, username);
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
