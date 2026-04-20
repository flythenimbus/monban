/*
 * pam_monban.so — PAM module that delegates authentication to
 * /usr/local/bin/monban-pam-helper.
 *
 * The helper in turn talks to the admin-gate plugin inside the user's
 * Monban app over a Unix socket. Exit 0 from the helper → PAM_SUCCESS,
 * anything else → PAM_AUTH_ERR so the next PAM rule (typically the
 * normal password prompt) runs.
 *
 * Install location: /usr/local/lib/pam/pam_monban.so
 * Referenced from : /etc/pam.d/sudo_local
 */

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define HELPER_PATH "/usr/local/bin/monban-pam-helper"

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;
    (void)argc;
    (void)argv;

    /* Pass the PAM user + service into the helper's environment so it
     * can find the right ~/.config/monban/plugins/admin-gate/ and
     * label the prompt ("Authenticate for sudo"). */
    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) == PAM_SUCCESS && user != NULL) {
        setenv("MONBAN_PAM_USER", user, 1);
    }
    const void *service_item = NULL;
    if (pam_get_item(pamh, PAM_SERVICE, &service_item) == PAM_SUCCESS && service_item != NULL) {
        setenv("MONBAN_PAM_SERVICE", (const char *)service_item, 1);
    }

    pid_t pid = fork();
    if (pid < 0) {
        return PAM_SYSTEM_ERR;
    }

    if (pid == 0) {
        /* Child: exec the helper. */
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
