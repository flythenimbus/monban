# Sourced by postinstall at install time and by cleanup-legacy.sh during
# uninstall so both agree on which authorizationdb rights the bundle
# rebinds to monban-auth.
#
# Keep ONLY "authorization" operations here — unlocking a preference pane
# or confirming admin intent. Rights that downstream Apple code expects
# to come with a real password in the auth context (Directory Services
# ops like system.preferences.accounts, system.services.directory.configure,
# system.csfde.requestpassword) must NOT be added — those crash Apple's
# own code when our plugin returns Allow without a password. They fall
# through to the normal password prompt, which is acceptable for rare
# destructive operations.

GATED_RIGHTS=(
    system.preferences
    system.preferences.security
    system.preferences.network
    system.preferences.sharing
    system.preferences.datetime
    system.preferences.energysaver
    system.preferences.printing
    system.preferences.softwareupdate
    system.preferences.startupdisk
    system.preferences.timemachine
)
