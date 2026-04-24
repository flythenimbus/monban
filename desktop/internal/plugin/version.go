package plugin

// HostAPIVersion is the plugin host API version this build of Monban
// implements. Plugins declare the version they target in their manifest's
// monban_api field.
//
// Pre-1.0: every minor bump is breaking. Plugins built against 0.1 will not
// load on a host with 0.2. Compatibility promises start at 1.0.
const HostAPIVersion = "0.1"
