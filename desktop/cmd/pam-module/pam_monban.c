/*
 * pam_monban.so — PAM module that delegates authentication to monban-pam-helper.
 *
 * Install: sudo cp pam_monban.so /usr/local/lib/pam/
 * Usage in /etc/pam.d/sudo_local:
 *   auth sufficient pam_monban.so
 */

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define HELPER_PATH "/usr/local/bin/monban-pam-helper"

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    pid_t pid = fork();
    if (pid < 0)
        return PAM_SYSTEM_ERR;

    if (pid == 0) {
        /* Child: exec the helper binary. */
        execl(HELPER_PATH, HELPER_PATH, NULL);
        _exit(127); /* exec failed */
    }

    /* Parent: wait for the helper. */
    int status;
    if (waitpid(pid, &status, 0) < 0)
        return PAM_SYSTEM_ERR;

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return PAM_SUCCESS;

    return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}
