# Update Sable safely

Treat a release update as a small, verifiable rollout. Preserve a recovery point, choose the intended channel, and confirm the running version after restart—not only the downloaded version.

## Before an update

Development builds (`dev`, unversioned builds, and versions marked `dev` or `snapshot`) disable release checks and self-update installation. About shows **Development build** instead of offering a published release. Rebuild from source to update a development checkout. Published alpha, beta, and release-candidate builds use the normal update workflow.

Read the target release notes, export a [sealed backup](../backup.md), and make sure you can restore it. Record the running version and important listener settings. Keep console or SSH access independent of the DNS service you are changing.

Database, backup-format, and cross-version cluster compatibility are not yet a published long-term contract. A successful binary downgrade is not proof that newer persistent data is safe for the older build. Use a known-good pre-upgrade backup when recovery requires the older state.

## Update a native installation

```sh
sudo sable update --check
sudo sable update
```

Sable selects the platform archive, checks its published SHA-256, runs the downloaded executable's version command, replaces the executable, and restarts the installed service. Use `--version TAG` for an exact published build, `--pre-release` to consider candidates, and `--no-restart` when you deliberately want to restart later.

After replacement, the previous executable is not a permanent rollback archive. Keep the backup and know where to obtain the previous release.

## Use the console deliberately

The **About** page can check on both primary and replica nodes. Installing requires `updates.apply` and a deployment that opted into writable service binaries:

```sh
sudo sable install --enable-web-updates
```

For Docker, opt in with `SABLE_WEB_UPDATES=true` and retain a restart policy. Otherwise update by pulling and recreating the immutable container image with the same volume.

The console installs first and then offers a controlled restart. The old process keeps serving until that restart. The **Include pre-releases** preference is saved per node, including on replicas; changing one node's channel does not change the whole cluster.

## Roll through a cluster

1. Back up the primary and choose one exact target version.
2. Update a replica.
3. Verify its DNS transports, console, and synchronization generation.
4. Update the primary to the same target.
5. Verify both versions and query each node independently.

Keep mixed-version windows short. Avoid combining an update with promotion unless the recovery plan requires it. See [rolling updates](../clustering.md#rolling-updates).

## Verify or recover

Check `sable version`, process health, a public lookup, an authoritative record, and the cluster generation when applicable. Open About again to confirm the running build.

For opted-in containers, a staged executable runs only when it is newer than the image's build. A newer image takes precedence; removing the opt-in setting makes the image authoritative again. Understand that rule before trying to pin an older image for recovery.

If startup fails, preserve the logs and use the [restore procedure](../backup.md#restoring-onto-a-fresh-instance). Do not repeatedly switch binaries against a database whose compatibility you have not established.
