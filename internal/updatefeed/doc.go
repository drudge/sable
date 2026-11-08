// Package updatefeed serves a disposable, loopback-only GitHub release feed
// for one locally built Sable binary, and builds binaries labeled with a
// release version. Binaries built with the updatedemo tag read the feed's URL
// from SABLE_DEMO_RELEASE_API, so the update demo and the cluster fault
// harness can run real updates without publishing a release.
package updatefeed
