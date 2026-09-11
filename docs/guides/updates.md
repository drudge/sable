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

The console checks for releases after sign-in by default on both primary and
replica nodes. A dismissible notice offers **Release notes** and **Install update**
without leaving the current page. Results, including failed checks, are cached for six hours per node;
manual checks remain available. Nothing is installed automatically.

Under **Settings → General → Software Updates**, turn off **Check for updates on sign-in** to disable automatic
checks on this node, or set `updates.check_on_login = false` in `sable.toml`.
The choice persists across restarts and is not replicated. Update readers can
see notifications; changing the preference requires `settings.write`.

The **About** page displays release notes and links the installed version to its
GitHub release. Release notes from a successful check or installation survive
restarts and remain readable while offline. It can check on both primary and replica nodes. Installing requires `updates.apply` and a deployment that opted into writable service binaries:

```sh
sudo sable install --enable-web-updates
```

For Docker, opt in with `SABLE_WEB_UPDATES=true` and retain a restart policy.
This flag also enables rolling restarts; no additional TOML setting is required.
Installed systemd services are detected automatically. For other external
supervisors, set `updates.restart_managed = true` after verifying that the
supervisor restarts Sable when it exits. Changes take effect when Sable next
starts. Otherwise update by pulling and recreating the immutable container
image with the same volume.

The console installs first and then offers a controlled restart. The old process keeps serving until that restart. The **Include pre-releases** preference is saved per node, including on replicas; changing one node's channel does not change the whole cluster.

## Roll through a cluster

From the primary, open **Cluster → Rolling Updates**, review **Release notes**,
and choose **Update all**. The update notification also offers **Entire cluster**
in its scope dropdown when every node supports rolling updates. The dropdown
remembers the last selection per user in this browser; its main button becomes
**Update cluster** or **Install update** accordingly. This requires both `updates.apply` and
`cluster.write`. The rollout pins that exact release across every node, even if
a newer release is published during the operation.

All nodes must be online, fully synchronized, running a published build with
rolling update support, and configured for writable binaries and automatic
restart. An older node without this protocol continues synchronizing normally,
but must be upgraded manually before it can join an automated rollout. Downgrades
are rejected; nodes already at the target version are skipped.

The primary reserves the update mechanism on every node, updates each replica
in order, and waits until it reports the target running version and current
configuration generation. It restarts only when every other node is online and
synchronized. The primary updates last, briefly interrupting its console, then
verifies the cluster after its restart. The Cluster page keeps progress visible
through restarts and marks the version badge with a green check when finished.

Progress is saved to the node's cluster data directory. A failure or timeout
stops further restarts; **Stop rollout** also prevents further nodes from
restarting. An installation or restart already authorized may finish. If the
coordinator restarts unexpectedly, the rollout stops for operator review. Review
partially updated nodes before starting another rollout; an installed binary
may need a manual restart first. When a primary disappears or changes, a replica
never restarts from stale instructions; abandoned reservations expire after
20 minutes without commands.

Configure clients or your load balancer with multiple DNS servers. Rolling
updates keep other nodes serving, but a client pinned to one restarting node
can still experience an interruption. Keep mixed-version windows short and
avoid changing cluster membership during a rollout. See
[rolling updates](../clustering.md#rolling-updates).

## Verify or recover

Check `sable version`, process health, a public lookup, an authoritative record, and the cluster generation when applicable. Open About again to confirm the running build.

For opted-in containers, a staged executable runs only when it is newer than the image's build. A newer image takes precedence; removing the opt-in setting makes the image authoritative again. Understand that rule before trying to pin an older image for recovery.

If startup fails, preserve the logs and use the [restore procedure](../backup.md#restoring-onto-a-fresh-instance). Do not repeatedly switch binaries against a database whose compatibility you have not established.
