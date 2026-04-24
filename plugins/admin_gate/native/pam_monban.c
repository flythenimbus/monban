/*
 * pam_monban.so — PAM module that delegates authentication to
 * /Library/Monban/monban-pam-helper.
 *
 * The helper in turn talks to the admin-gate plugin inside the user's
 * Monban app over a Unix socket. Exit 0 from the helper → PAM_SUCCESS,
 * anything else → PAM_AUTH_ERR so the next PAM rule (typically the
 * normal password prompt) runs.
 *
 * Install locations (N20 — /Library/ is root-owned by default on
 * macOS and cannot be user-chowned without explicit admin action,
 * unlike /usr/local/ which is user-writable on Intel Macs with
 * Homebrew):
 *   /Library/Monban/monban-pam-helper
 *   /Library/Monban/pam/pam_monban.so
 * Referenced from: /etc/pam.d/sudo_local
 */

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define HELPER_PATH "/Library/Monban/monban-pam-helper"

/*
 * helper_is_safe refuses to exec the PAM helper unless it's owned by
 * uid 0 and not group- or world-writable. Same-uid malware that
 * overwrites the helper (e.g. via a misconfigured /Library/Monban/
 * perm set) is caught here before the SUID-root PAM stack hands it
 * arbitrary control.
 */
static int helper_is_safe(void) {
    struct stat st;
    if (stat(HELPER_PATH, &st) != 0) return 0;
    if (!S_ISREG(st.st_mode)) return 0;
    if (st.st_uid != 0) return 0;
    if (st.st_mode & (S_IWGRP | S_IWOTH)) return 0;
    return 1;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;
    (void)argc;
    (void)argv;

    if (!helper_is_safe()) {
        return PAM_AUTH_ERR;
    }

    /*
     * Resolve the PAM user + service before fork so we can pass them
     * to the child without relying on libpam in the post-fork context.
     */
    const char *user = NULL;
    const void *service_item = NULL;
    (void)pam_get_user(pamh, &user, NULL);
    (void)pam_get_item(pamh, PAM_SERVICE, &service_item);

    pid_t pid = fork();
    if (pid < 0) {
        return PAM_SYSTEM_ERR;
    }

    if (pid == 0) {
        /*
         * Child only: set MONBAN_PAM_* in this process's env so the
         * helper can read them. N22: setting these in the parent would
         * leak them into sudo's own environment, which the target
         * command then inherits. Forking first and writing env in the
         * child keeps the leak contained to this short-lived process.
         */
        if (user != NULL) {
            setenv("MONBAN_PAM_USER", user, 1);
        }
        if (service_item != NULL) {
            setenv("MONBAN_PAM_SERVICE", (const char *)service_item, 1);
        }
        execl(HELPER_PATH, HELPER_PATH, (char *)NULL);
        _exit(127); /* exec failed */
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        return PAM_SYSTEM_ERR;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return PAM_SUCCESS;
    }

    return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
