# Changelog

This file records the user-visible changes selected for Sable releases. GitHub
release notes require a matching version section, including release candidates.
Generated commit lists are never published as release notes.

Create a passphrase-sealed application backup before upgrading and keep
mixed-version cluster windows short. Cross-version restore and downgrade
compatibility are not yet a published contract.

## [1.5.0-beta.10] - 2026-09-26

Sable 1.5.0-beta.10 tidies the console. The sidebar fits a laptop screen and
groups its pages more clearly, every device draws the console in Inter, and
About credits the open-source software Sable is built on.

### Sidebar

- Fit the whole sidebar in a laptop-height browser window, so **About** no
  longer sits cut off at the bottom.
- Drop the **Overview** heading over the first group, and list
  **Administration**, **Cluster**, **Integrations**, **Settings**, and
  **About** under **System**. **Integrations** moves there from the first
  group, and the command palette lists pages in the same order.
- Scroll the sidebar in a window too short for it, with the fade and chevron
  phones already show, and keep the current page in view.
- Blur the page behind the open phone menu and fade in its dimming, as
  dialogs do.

### Console

- Ship the Inter font with the console, so every device draws the same text.
  Before, only a device with Inter installed drew it, and phones fell back to
  their own font.
- Credit the open-source software Sable is built on: **Third-Party Licenses**,
  in About's **MIT License** dialog, lists each project with its license.
- Stack a dialog's buttons on a phone with the one that only closes it,
  **Cancel**, **Close**, or **Done**, at the bottom, the way iOS does.
- Lay the ten **Settings** tabs out in two rows of five on phones at least
  375px wide, instead of leaving two alone on a third row.

### Alerts

- Call the switches for each kind of alert **Alert Types** instead of groups,
  in **Settings > Alerts** and in a destination's **Only These Types** choice.
  The configuration and webhook JSON keep their names.

### Fixes

- Stretch the Insights time range picker across the full width of a phone
  screen.
- Keep the note on the **Alerts** card to one line while alerts are paused.

## [1.5.0-beta.9] - 2026-09-26

Sable 1.5.0-beta.9 keeps button labels on one line in Safari.

### Console

- Keep **Send Test** on one line on each alert destination in Safari, where
  its button came out slightly too narrow for its label.
- Keep small buttons with an icon on one line in Safari on a phone, such as
  **Add Destination**, **Add Key**, and **Set Up UniFi Sync**.

## [1.5.0-beta.8] - 2026-09-26

Sable 1.5.0-beta.8 turns Insights alerts into alerts for the whole server.
Set them up under **Settings > Alerts** and hear about nodes going down,
failed backups, failing integrations, certificate and zone trouble, new
releases, and bursts of failed sign-ins, along with Insights findings. You
can also choose what Insights does with each kind of finding, and phones'
rotating private IPv6 addresses no longer show up as new or quiet devices.

### Alerts

- Set up alerts under **Settings > Alerts** instead of in Insights. An
  existing Insights webhook becomes the first destination on the next start,
  and nothing it already sent goes out again.
- Add as many destinations as you need, each a webhook, ntfy topic, Slack or
  Discord channel, Pushover, or your browsers, and send each one
  **Everything** or **Only These Groups**.
- Keep destination URLs, Pushover keys, and header values in the encrypted
  vault instead of `sable.toml`. Saved ones move there on the next start and
  show cut short when you edit a destination.
- Turn groups of alerts on or off: Insights Findings, Cluster, Sable Updates,
  Integrations, Backups, Server Health, and Failed Sign-Ins.
- Send problems, such as a node going down or a backup failing, at high
  priority on ntfy, Pushover, and browsers.
- Keep sending to every other destination when one fails, and show each
  destination's last send or last error.
- Send an alert once for as long as it stays news. Before, one that lasted
  more than six hours could go out again.
- Turn on browser alerts from the **Browsers** destination's row, which lists
  every browser that turned them on. Removing Browsers forgets them all.

### New alerts

- **Cluster:** a node that has not checked in for five minutes, and again
  when it comes back. A node restarting for an update within those five
  minutes says nothing. If the lead stops answering, a replica says so after
  five minutes, unless a planned handoff gave the cluster a new lead. Rolling
  updates alert when they start, finish, fail, or stop.
- **Sable Updates:** a release newer than the one running.
- **Integrations:** UniFi sync or dynamic DNS failing three times in a row,
  and a new public IPv4 or IPv6 address, with the address it replaced.
- **Backups:** a scheduled backup that fails, or every backup as it finishes.
- **Server Health:** a certificate renewal failing near expiry or three times
  in a row, a secondary zone that stops refreshing or expires, and DNSSEC
  root keys that stop updating. Certificates installed by hand are left out.
- **Failed Sign-Ins:** off unless you turn it on. One alert for each burst, 5
  failures within 10 minutes unless you change it, with the usernames tried
  and the addresses they came from.

### Clusters

- Copy alert settings, their secrets, and the browsers that turned alerts on
  to every node, so a new lead keeps sending to the same places. Only the
  lead sends, so each alert arrives once.
- Send each replica's own backup, certificate, zone, and DNSSEC problems
  through the lead.
- Copy Insights settings to every node.

### Insights

- Choose what Insights does with each kind of finding, **Show and alert**,
  **Show only**, or **Off**, and change the limits behind it, such as how much
  busier than usual a device must get. Open **Settings** beside the range
  control. Alerts for each kind can also be switched under Insights Findings
  in **Settings > Alerts**.
- Show whether Insights alerts are **On**, **Paused**, or **Off** on the bell
  beside **Settings**, say why when you hover over it, and open
  **Settings > Alerts** from it.
- Stop reporting a phone's or computer's private IPv6 address, which changes
  about once a day, as a new address or one that went quiet.
- Tie a device's older IPv6 addresses to it across the whole two weeks that
  Went quiet, Unusually busy, and Active at an unusual hour look back, so last
  week's address no longer looks like a device that went quiet and the phone
  no longer looks unusually busy. Tie IPv6 addresses built from a hardware
  address to that hardware right away.

### Software updates

- Look for a new Sable release in the background on the lead node, so an
  update alert does not wait for someone to sign in. Check **Hourly**, the
  default, **Daily** at a time, or **Weekly** on a day and time, under
  **Settings > General > Software Updates**. Turning off **Check for updates**
  stops these checks too.

### Audit log

- Record the username a failed password sign-in tried, never the password.
- Record each password, single sign-on, and passkey lockout once.

### Fixes

- Show the last good scheduled backup on the Backup tab after a restart
  instead of nothing.
- Stop reporting a second, false failure for a rolling update that had
  already ended.
- Return focus to the button that opened a dialog even when saving redraws
  the page behind it.

### Configuration

- Add `[alerts]` with `paused`, `[alerts.send]` for the groups,
  `[alerts.sign_ins]`, and `[[alerts.destinations]]`. `[insights.webhook]`
  still loads and moves into `[[alerts.destinations]]`.
- Add `[insights.findings]`, with a mode and limits for each kind of finding.
- Add `check_schedule`, `check_at`, and `check_day` to `[updates]`.

## [1.5.0-beta.7] - 2026-09-24

Sable 1.5.0-beta.7 draws the ChatGPT and Microsoft 365 logos the way their
apps do, and closes DNS-over-QUIC connections cleanly when Sable stops.

### Insights

- Show ChatGPT's logo in black on white, like its app, instead of on
  OpenAI's old purple.
- Show Microsoft 365 with Microsoft's four-color logo on white instead of
  Office's retired mark.

### DNS over QUIC

- Tell a client that connects just as Sable stops that the connection is
  closing, so it reconnects right away instead of waiting for its idle
  timeout.

## [1.5.0-beta.6] - 2026-09-24

Sable 1.5.0-beta.6 fixes turning on browser alerts in browsers whose push
service is switched off, tidies the Alerts dialog, and gives many more apps
their logos in Insights.

### Insights alerts

- Turn on browser alerts even when the browser cannot read back an old
  subscription, and say how to switch a browser's push service back on when
  it is off, as in Brave by default or in Firefox and Zen with
  `dom.push.connection.enabled` turned off, instead of showing "Error
  retrieving push subscription."
- Fit all six **Send To** choices on one line, and show **Remove** for a
  browser in red like other removals.

### Insights

- Show the logos of ChatGPT, Microsoft 365, Microsoft Teams, OneDrive, Bing,
  Microsoft services, Slack, LinkedIn, Amazon, Prime Video, Alexa, Fire TV,
  Xbox, Nintendo, and Adobe, kept from the last Simple Icons releases that
  carried them.

## [1.5.0-beta.5] - 2026-09-24

Sable 1.5.0-beta.5 gives Insights alerts more places to go and makes sure
they get there. Alerts can go to your browsers as notifications, to Slack and
Discord as rich cards, or to Pushover, and Sable now checks that the service
it sent to actually took the message instead of trusting any answer.

### Insights alerts

- Send alerts straight to your browsers with **Browser**. Turn it on in each
  browser that should get them; notifications show up even when Sable is
  closed, and no account or app is needed. Browsers allow this only when
  Sable is opened over HTTPS or at `localhost`, and on iPhone and iPad only
  after Sable is added to the Home Screen.
- Send alerts to Slack as a card with a colored bar for how much a finding
  matters, its reasons, and a button to Insights, and to Discord as an embed
  in the same colors that never mentions anyone.
- Send alerts to Pushover with just your application token and user key.
- Pick where alerts go under **Send To**, with each service's mark. A URL
  entered for one service stays with it when you look at another.
- Check that ntfy, Slack, Discord, Pushover, and browsers actually took an
  alert. Before, any server that answered counted as sent, so a mistyped URL
  such as a parked domain looked like it worked. For ntfy, turn on **Check
  for an ntfy Receipt** under **Advanced**.
- Pause and resume alerts without losing their setup. Findings that turn up
  while alerts are paused are not sent when they resume.
- See exactly what an alert sends with **Preview**, with tokens cut short,
  and copy it.
- Add headers to webhook and ntfy alerts under **Advanced**, such as
  `Authorization` for a protected ntfy topic or `Priority`.

### Console

- Show a message from inside a dialog above the dialog instead of behind its
  blurred backdrop.

## [1.5.0-beta.4] - 2026-09-24

Sable 1.5.0-beta.4 lets Insights show its evidence instead of only listing it.
Findings chart what changed, devices and apps are recognizable at a glance,
and the Overview opens with one sentence you can act on. The console also
reloads itself once an update finishes, so it runs the new release right away.

### Insights

- Chart the evidence in a finding's details: a device that went quiet or got
  busy against each day of its week before, one active at an unusual hour
  against its usual day, and a check-in as one mark per lookup across the
  last day. Point at or tap a bar to read its count, or drag across the bars
  on a phone.
- Open the Overview with one sentence about what stands out. Each device it
  names opens its finding, and the list below it is now **Worth a Look**.
- Open Top Apps and Busiest Devices entries in drawers. An app's drawer lists
  the domains it used, each linked to its queries, and the devices that used
  it. Apps and devices open each other's drawers.
- Show app logos in each brand's color for most of the apps Insights
  recognizes, and a category icon for the rest.
- Show what each device is as an icon at the start of its row and beside its
  name, in place of the Type column, and in the type picker. Hover the icon
  to read the type.
- Move alert setup behind a bell beside the range control, which shows
  whether alerts are on.
- Jump to App, Device, and Blocking Insights, or straight to alert setup,
  from the command palette.
- Show a spinner while a device's name saves or is removed, and stop Enter in
  the name field from removing the name.
- Keep a finding's fact cards in pairs without gaps, and give a long DNS name
  a row of its own instead of wrapping it mid-name.
- Write TV in capitals when describing a device's type.

### Updates

- Reload the console once an update finishes, so it runs the new release: at
  the end of a rolling update watched from the Cluster page, and when an
  installed update finishes because Sable was restarted outside the console,
  such as by its service manager.
- Start or follow a rolling update from the command palette with **Update
  Cluster**.

### Console

- Make every View all an ordinary button with a chevron, centered in its
  card's header, and count apps and devices, not domains, in their full lists.

## [1.5.0-beta.3] - 2026-09-23

Sable 1.5.0-beta.3 settles how devices are named and teaches Insights to
recognize Sable itself. A device keeps the same name from one visit to the
next, and Sable's own scheduled lookups are no longer reported as a device
phoning home.

### Insights

- Name every device in one order: the name you gave it, then UniFi's, then a
  local host override, then reverse DNS. A UniFi name no longer gives way to
  reverse DNS whenever the server's neighbor table saw the device more
  recently than the controller did.
- Mark the machine Sable runs on as **This server** and the rest of its
  cluster as **Sable node**, and count running Sable as a clue that a device
  is a server.
- Leave out what Sable looks up for itself on a timer, such as dynamic DNS
  updates, UniFi sync, and block list downloads, when looking for check-ins,
  so a server with dynamic DNS is no longer reported for calling its DNS
  provider every five minutes.
- Remove a device's name or type completely. One given while Sable only knew
  the device's IP address stayed behind once Sable learned its hardware
  address, so removing it said it worked while the device kept it.
- Say when a device's name or type comes from an entry for its whole network,
  and stop offering to remove that name from one device. Handing a device's
  type back names the network's type it will take.

### Dashboard

- Name top clients the way Insights names devices, so your names and UniFi
  names show there too, ahead of host overrides and reverse DNS.

## [1.5.0-beta.2] - 2026-09-23

Sable 1.5.0-beta.2 makes Insights fast on a real month of history. Tested with
a month of busy network traffic, about seven million queries, the page took
fifteen seconds to open and still left sections empty. It now opens in about a
second, and after that answers from its last count while a fresh one runs.

### Insights

- Keep hourly and daily totals of the query log alongside the per-minute
  ones, and read whole hours and days from them, so a month is thousands of
  rows instead of millions. After upgrading, Sable fills them from existing
  history in the background, which takes about a minute for a busy month;
  until then Insights reads the minutes as before.
- Count the blocked queries each device made before 1.5.0-beta.1 once, in the
  background, instead of reading them from the raw query log on every visit.
- Look for scheduled check-ins in the last day of queries alone, rather than
  in each name's whole history.
- Answer from the last count while a fresh one runs, and start every slow read
  at once when the page opens, so only the first visit after a restart waits.
- Keep showing the last block list comparison while a refreshed list is
  compared again. Adding or removing a list still waits for the new one.
- Read a device's busiest domains by time or by device, whichever is shorter
  for its traffic and the selected range.
- Open a device's details from anywhere on its row. The Devices table drops
  its history columns, and on narrow screens becomes a list, before a row can
  run past the edge of the card and hide its details button.
- Start the device drawer from its loading state when opening another device,
  instead of showing the previous one until the new one arrives.
- Show Sable's spinner in the Insights and dashboard update indicator, and
  keep its text on one line.

### Dashboard

- Rank clients and domains for longer ranges from the hourly and daily
  totals as well.

## [1.5.0-beta.1] - 2026-09-23

Sable 1.5.0-beta.1 introduces Insights: a local view of what changed on your
network, what each device is, and what is worth a look. Every finding shows
the evidence behind it and links to the exact queries it counted. Insights uses
fixed rules and lookup tables on your own server, with no machine learning or
cloud service, and none of it runs on the DNS request path.

### Insights

- Add an Insights page with Overview, Devices, and Blocking tabs, reachable
  from the sidebar and the command palette with either logs or blocking read
  permission.
- Open the Overview with one sentence about what stands out, followed by
  network metrics, the findings behind it, Top Apps, and Busiest Devices.
- Explain every finding in a drawer with fact cards, the reasons Sable
  surfaced it, what it could mean, and the rule that produced it, with copy
  buttons for addresses and names and a link to the matching query log rows.
- Report new devices, devices that went quiet or became unusually busy,
  devices active at an hour they never use, appliances such as cameras and
  doorbells that start calling new services, devices that start using a new
  app, and names only one device looks up on a steady schedule.
- Fill device history from the existing query log after upgrading, so
  Insights knows which devices were already on the network from the first day.
- Let operators dismiss a finding for a day, snooze it for a week, or mark it
  normal, with hidden findings listed and restorable. Feedback is kept by the
  device's hardware address, so it survives renames.
- Send each new finding worth a look to an optional webhook, once, in JSON
  for Slack, Discord, and Home Assistant or plain text for ntfy. A new webhook
  takes stock quietly instead of receiving old news, only the primary node
  sends, and the webhook URL is never stored in the database.

### Devices

- Group client addresses into devices by hardware address using UniFi, the
  server's neighbor table on Linux and macOS, and names you give, so a
  device's IPv4 and changing IPv6 addresses count as one.
- Name devices from your own names, UniFi, local host entries, and reverse
  DNS, with a badge showing where each name came from, and rename a device
  from its drawer.
- Name each device's maker from the IEEE registry built into Sable, and guess
  its type from the maker, its name, and the services it talks to, with a
  confidence level and the clues behind it. Correct a wrong guess from the
  device drawer; the correction follows the hardware address.
- Name the apps behind domains from a built-in catalog, and list each
  device's apps, busiest domains, and first-time domains.

### Blocking

- Record which block list supplied the rule behind every blocked query and
  show it in the query explanation.
- Compare enabled block lists by the domains only they cover, their largest
  overlap, and the blocked queries each one accounted for alone.
- Find names that were blocked before an operator allowed them, and block
  lists that stopped updating or could not be read.

### Configuration

- Add `type` to `[[clients]]` entries, and allow an entry to set a name, a
  type, or both.
- Add `[insights.webhook]` with `url` and `format` for Insights alerts.

## [1.4.0] - 2026-09-18

Sable 1.4.0 gives the console a more deliberate visual hierarchy across desktop
and mobile, with clearer data-first layouts, calmer surfaces, and more useful
dialogs and maintenance controls.

### Console polish

- Refine the desktop shell with a rounded workspace surface, clearer sidebar
  hierarchy, and consistent muted treatments for table headers, card headers,
  and action footers.
- Standardize compact rounded controls, icon actions, dialog and toast close
  buttons, button heights, and subtle borders across the console.
- Improve tab hover and focus states so inactive controls remain discoverable
  without competing with the selected tab.
- Improve expanded, collapsed, and mobile sidebar spacing, touch targets,
  selection states, and responsive navigation behavior.
- Make dialogs, release notes, license text, and ranking views feel like part
  of the same console, with readable scroll regions and distinct action
  footers.

### Responsive workflows

- Prioritize DNS record names and values on phones while reducing the visual
  weight of TTL and integration metadata.
- Give narrow zone detail headers a deliberate title-and-actions layout,
  preserve readable record values at tablet widths, and keep a clear gap
  before trailing record actions.
- Improve mobile layouts for blocking actions, cluster actions, sidebar
  navigation, forms, and record editors, including scroll locking and visual
  cues when navigation continues below the viewport.
- Let record editor descriptions wrap on mobile, including SOA editors,
  without clipping the form or its controls.
- Collapse the DNS cache explainer by default on phones while keeping it open
  on larger screens.
- Keep long names, values, descriptions, and license text readable instead of
  allowing cramped layouts to clip the surrounding controls.
- Show record names relative to their zone by default, with a browser display
  preference for operators who want fully qualified names.

### Cluster and maintenance

- Clarify cluster identity and node status with stronger value contrast,
  updated-state badges, and consistent shaded status and action footers.
- Improve rolling-update and blocking-maintenance controls across narrow
  screens, including better button grouping and next-update presentation.
- Add a seeded Air-backed demo workflow with automatic login after restart,
  while preserving the normal login flow after an explicit sign-out.

### Logs and administration

- Make Query Logs follow new entries by default, matching Server Logs, while
  preserving explicit pause, filtering, paging, and incremental refresh.
- Improve log toolbar wrapping and mobile readability, and keep zone import
  actions compact and clearly menu-driven.

### Command palette and notifications

- Add a direct **Block Lists** page action.
- Add quick actions for restoring a backup and creating a backup with the
  configured passphrase, with an alternate-passphrase path when needed.
- Keep the frontmost update notification fully readable and anchored to the
  bottom of the console, including when it is taller than a transient toast.
- Keep older notifications visible as compact cards behind the frontmost
  update card, while preserving hover and keyboard-focus expansion.

### Sign-in and attribution

- Move the Sable brand outside the sign-in panel and simplify the welcome copy
  for a cleaner authentication screen.
- Present passkey failures using the same prominent status treatment as other
  sign-in errors.
- Show the MIT license in an in-app dialog, with an option to view the source
  license in the repository.

## [1.3.5] - Unreleased

Sable 1.3.5 makes everyday administration faster and safer, with particular
improvements to large catalog imports, backups, cluster maintenance, DNS
configuration changes, and service shutdowns.

### Faster administration

- Review large catalog imports with substantially less processing and memory
  use, and open **Import from Catalog** directly from the command palette.
- Refresh live cluster status with less background work, even when several
  updates arrive together.
- Limit client-name lookup traffic and memory use when multiple console views
  are open.

### Safer backups and maintenance

- Reliably enforce the configured scheduled-backup retention limit without
  deleting manual, imported, invalid, or other-node archives.
- Show backup history and next and last run times using your configured time
  zone and preferred 12- or 24-hour clock.
- Add drag-and-drop file selection when uploading a backup to restore.
- Let in-progress backup, restore, DNS refresh, and logging work finish safely
  during shutdown. New background work is refused once shutdown begins, and
  incomplete shutdowns no longer write a potentially inconsistent DNS cache.

### Predictable DNS configuration changes

- Apply forwarding changes immediately by discarding answers cached under the
  previous rules and isolating lookups that began before the resolver reload.
- Stop DNS prefetch and stale-answer refresh work cleanly before releasing the
  resources it uses during shutdown or failed startup.

### A more dependable console

- Present update notices and success or error messages in one consistent
  notification stack. Multiple notices collapse into a compact deck, expand
  smoothly on hover or keyboard focus, and pause timed dismissal while you
  inspect them.
- Keep command-palette and form actions from submitting twice, report request
  failures instead of announcing success, and preserve useful validation and
  permission errors.
- Recover cleanly when a session expires by sending the browser to login or
  setup instead of placing an authentication form inside the current page.
- Save profile changes without JavaScript and return invalid entries with a
  useful error message.
- Clean up interactive controls as page sections refresh, avoiding accumulated
  handlers during long console sessions.
- Hide transient rolling-update capability warnings while an update is already
  running, and keep release-version badges readable.

### Interface refinements

- Use accessible switches for independent on/off settings and clearer states
  for disabled controls.
- Improve cluster-node spacing, status-metric layouts, light-mode navigation
  contrast, and hover and selection treatments across the console.
- Add clear, item-specific confirmation dialogs before removing block lists or
  individual allowed and blocked domains, with a softer blurred backdrop that
  keeps attention on the decision.
- Keep the scheduled-backup time picker visible and clarify which archives its
  retention setting controls.
- Make replica removal easier to distinguish from promotion by using the
  established outlined destructive style.

## [1.3.5-rc.5] - Unreleased

This fifth release candidate includes the reliability fixes from 1.3.5-rc.4
and polishes backup, settings, and cluster workflows in the web console.

- Enforce scheduled-backup retention at startup, after policy changes, and
  after successful archive creation. Manual, imported, invalid, and other-node
  archives remain untouched.
- Show backup history and next/last run times in the operator's preferred time
  zone and 12- or 24-hour format, without adding a one-off timezone suffix.
- Keep the scheduled-backup time picker visible outside its settings card and
  clarify that the retention limit applies only to scheduled archives.
- Use the catalog import dropzone behavior for uploaded restores, including a
  solid drop target, animated selected-file state, inline backup identity, and
  clearer replacement warnings.
- Render independent boolean settings as accessible switches while preserving
  their existing form behavior and disabled states.
- Improve cluster-node spacing and light-mode sidebar selection contrast, and
  hide transient capability warnings while a rolling update is already active.

## [1.3.5-rc.4] - Unreleased

This fourth release candidate includes the reliability fixes from 1.3.5-rc.3
and polishes authentication transitions and the web console layout.

- Redirect expired or unauthenticated partial-page requests to login or setup
  at the browser level, preventing authentication forms from appearing inside
  the existing console frame.
- Make shared status metrics more compact, with right-aligned values,
  accessible description tooltips, consistent wrapping, and balanced spacing.
- Add consistent hover and selection borders to sidebar and outlined controls.
- Place **Remove Replica** before promotion, align it to the left, and use the
  established outlined destructive style.

## [1.3.5-rc.3] - Unreleased

This third release candidate includes the improvements from 1.3.5-rc.2 and
fixes DNS behavior during forwarding changes and background-job shutdown.

- Apply forwarding changes consistently: discard cached answers from previous
  zone forwarding rules and keep new lookups from sharing work started before
  a resolver configuration reload.
- Wait for stale-answer refreshes and manual backup/restore jobs during
  shutdown. Stop accepting new background jobs and report a timeout if work
  cannot finish safely before the shutdown deadline.
- Honor backup and restore cancellation at safe boundaries, including before
  scheduling a restore for the next restart.

## [1.3.5-rc.2] - Unreleased

This second release candidate includes the performance and reliability
improvements from 1.3.5-rc.1, plus two console fixes found during cluster testing.

- Open **Import from Catalog** directly from the command palette. The action
  follows zone-creation permissions and is hidden on read-only replicas.
- Keep release versions such as `v1.3.5-rc.1` on one line in the rolling-update
  badge instead of splitting the version across lines.

## [1.3.5-rc.1] - Unreleased

This first release candidate for Sable 1.3.5 improves performance and reliability across catalog imports, cluster
status, and the web console, with more orderly shutdowns and clearer feedback
when console actions fail.

### Faster imports and lighter background work

- Reduce processing time and memory use when reviewing large catalog imports.
- Reduce the work needed to refresh live cluster status and avoid repeating
  cluster configuration capture when multiple refreshes arrive together.
- Limit concurrent client-name lookups and bound their cache size, reducing
  background DNS traffic and memory use when several console views are open.

### A more reliable console

- Clean up dropdown, time-picker, and resolver controls when page sections are
  refreshed, preventing unused event handlers from accumulating over time.
- Show command-palette results consistently, including when the relevant page
  is not open. Prevent duplicate submissions while an action is running and
  report failed requests instead of announcing success.
- Preserve useful validation and permission errors for zone and blocking
  actions without replacing page content with an unformatted server error.
- Save your profile display name and email with JavaScript disabled. Invalid
  submissions return a full page with the entered values and an error message.

### More orderly shutdowns

- Stop background tasks and DNS prefetch work before releasing the resources
  they use during shutdown or failed startup.
- Cancel stalled query-log and server-log writes during shutdown and give
  queued entries a bounded opportunity to finish writing.
- Skip DNS cache persistence when shutdown is incomplete, avoiding a snapshot
  while background work may still be changing it.

## [1.3.4] - 2026-09-14

Sable 1.3.4 is a hotfix for cluster setup and certificate trust, including
replica enrollment after regenerating a private CA.

- Start initialization and reinitialization at the Node step with saved settings
  prefilled. Resume the final step after saving or completing a requested restart.
- Default fresh self-signed installations to **Sable Private CA** and prefill
  editable DNS service addresses from configured listeners and local interfaces.
- Support enrollment using the existing self-signed HTTPS certificate without
  disabling certificate hostname or expiration checks.
- Confirm replacement of an existing private CA before saving. **Cancel** leaves
  it unchanged; **Replace CA & Continue** creates new certificate files and
  preserves the previous CA and keys for recovery.
- Detect changed certificate trust even at unchanged file paths, require a
  restart, and reject enrollment-token creation while the loaded trust is stale.
  **Restart & Continue** resumes setup after the service manager restarts Sable.

Update both nodes before retrying enrollment with an existing self-signed server
certificate: older builds accept CA certificates only in enrollment bundles.
Generate a fresh token after the primary has restarted. Replacing a private CA
can invalidate existing tokens and member trust; this hotfix does not provide
seamless CA rotation for a running cluster. See the [cluster recovery procedure](https://github.com/drudge/sable/blob/main/docs/clustering.md#retry-a-failed-first-enrollment).

## [1.3.3] - 2026-09-13

Sable 1.3.3 is a hotfix for direct recursive DNS resolution. It fixes `.com`
delegation failures, DNSSEC validation after cached lookups, and failover when
an authoritative nameserver stops responding.

- Accept valid root-supplied addresses for `.com` nameservers under
  `gtld-servers.net`, fixing `delegation for com. has no resolvable name servers`.
  Referral addresses remain restricted to the named servers within the
  referring parent's scope.
- Query the parent authority for DNSSEC DS records even when a previous lookup
  cached the child delegation, allowing validation to follow the correct
  chain of trust.
- Reserve time for alternative authoritative nameservers so retries against a
  silent server cannot consume the entire resolution timeout before failover.

Existing recursive resolver configurations do not need to change. Conditional
forwarding routes and Forwarder zones continue to use their configured upstreams.

## [1.3.2] - 2026-09-13

Sable 1.3.2 lets you migrate Technitium forwarder zones with their local overrides,
keep them synchronized while you test, and move write ownership to Sable when
you are ready. It also improves zone-file imports and search controls throughout
the console.

### Migrate forwarder zones without rebuilding overrides

- **Zones → Import… → From catalog** now recognizes supported Technitium
  forwarder zones and preserves their forwarding rules and local records,
  instead of rejecting them for an unsupported record type or missing apex NS.
- Choose **Secondary** to create a read-only **Secondary Forwarder** that keeps
  receiving source changes. Choose **Primary** to create an independent,
  editable **Forwarder** after confirming that source writes are paused.
  Importing does not subscribe Sable to the source catalog's membership.
- Matching local answers take precedence before forwarding, including TXT and
  MX as well as A, AAAA, and CNAME. Queries without a matching local answer
  continue through the forwarding rules. Independent Forwarders allow adding
  ordinary records alongside FWD records in the console.
- Supported transfers preserve UDP, TCP, TLS, and QUIC forwarding, priorities,
  and consistent DNSSEC validation settings. Technitium's `this-server` rule
  uses Sable's default resolver: configured upstreams in forward mode, or
  iterative resolution in recursive mode.

### Keep source changes in sync, then take ownership

- Secondary Forwarders refresh by full AXFR on their SOA schedule, authorized
  NOTIFY, or **Resync**. Updates include changed forwarding rules and added or
  deleted overrides. Failed or invalid refreshes retain the last valid snapshot
  until SOA expiry; expired zones return SERVFAIL until synchronization recovers.
- **Actions → Convert to independent Forwarder** makes Sable the writable
  owner without deleting and recreating the zone. Pause source edits and
  automatic writers, review the snapshot, and use **Synchronize, then convert**
  to capture the final source changes.
- Conversion retains records, forwarding and validation settings, permissions,
  and history, advances the SOA serial, and stops source synchronization.
  A failed final transfer or stale review leaves the Secondary Forwarder
  unchanged. **Use the stored snapshot** explicitly skips the final transfer
  and may retain stale or expired data.

Sable catalog-managed members cannot use this conversion; stage independent
imports for migration. Source-wide resolver and proxy settings are not copied.
Unsupported forwarding options are reported per zone without creating that
zone. The separate zone-file importer does not support Technitium's full textual
FWD syntax. See the [migration guide](docs/guides/technitium-migration.md#forwarder-members)
for supported settings and the cutover procedure.

### Easier imports and consistent search

- A single **Import…** menu offers **From file or text** and **From catalog**.
  Zone-file dialogs support drag-and-drop uploads, a selected-file summary,
  and a separate text editor with **Paste from clipboard**. New-zone imports
  detect the zone name from the file when possible.
- Fix zone-file imports whose apex SOA owner is written as the full zone name
  without a trailing dot, while preserving other relative names.
- Keep catalog import controls positioned correctly as the dialog opens.
- Standardize search fields across the console, with consistent search icons
  and clear buttons for quickly resetting a query or filter.

## [1.3.1] - 2026-09-13

- Stack OpenID Connect and passkey sign-in buttons together, with a single
  **or** separator before password authentication.
- Keep the separator correct when either method is disabled or passkeys are
  unavailable in the browser. Initial administrator setup has no separator.

## [1.3.0] - 2026-09-13

Sable 1.3.0 adds native passkeys for standalone servers and clusters, making
passwords optional while retaining OpenID Connect and password sign-in.

### Passkeys and account access

- Register and manage passkeys in **Profile → Account**, below Account details.
  Sign in without a username using your device's fingerprint, face, PIN, or a
  security key. Passkeys require an HTTPS DNS hostname; localhost is supported
  for development. Unsupported browsers and ordinary HTTP connections hide
  passkey sign-in and registration controls.
- Disable password sign-in after adding a passkey, then re-enable the existing
  password without resetting it. Accounts without a password can set one.
  Credential removal and password controls use Sable's confirmation dialogs.
- Passkey public credentials replicate and are included in authorization
  backups. Existing HTTPS identities and cluster membership determine trusted
  origins, with a stable RP ID derived from the registrable domain. Nodes under
  the same domain can accept the same credential after replication.
- **Settings → Web → Enable passkeys** controls availability and defaults on.
  Disabling preserves saved credentials and blocks passkey authentication and
  enrollment. The settings form checks that active accounts have an enabled
  password or a link to the enabled OIDC provider before allowing the change.
- The [passkey guide](docs/guides/passkeys.md) covers enrollment, password
  recovery, standalone HTTPS, reverse proxies, cluster failover, and backups.
  Initial administrator setup still starts with a password.

### Update preferences

- Software Updates in Settings now includes **Include pre-releases** alongside
  **Check for updates on sign-in**. Both wait for **Save Settings**.
- The About page retains its release-channel control and shares the same saved,
  node-local preference with Settings.

## [1.2.0] - 2026-09-11

Sable 1.2.0 makes it easier to migrate authoritative zones from Technitium and
other DNS servers, with bulk catalog import, in-place conversion to Primary,
and clearer guidance throughout the cutover. It also improves the everyday
console experience on desktop and mobile.

### Import zones from a catalog

- A new **Zones → Import from Catalog** wizard connects to a source catalog,
  discovers its members, and lets you import up to 25 selected zones at a time.
  Configure the source servers, transfer protocol, and TSIG key in the dialog.
- Choose **Secondary** to keep zones synchronized with the existing DNS server
  while you test, or **Primary** to make Sable writable immediately. Primary
  imports require confirmation that source edits and automatic writers are paused.
- Imported zones are independent of the source catalog. This is a one-time
  import, not a catalog subscription; Sable's native cluster replication
  distributes the imported zones to its replicas.
- Existing Sable zones are left unchanged. Results show each zone's outcome,
  so a failed transfer does not discard successful imports. Catalog membership
  is checked again before importing to catch changes since discovery.
- Signed zones can be imported as Secondaries. Primary import is blocked until
  their DNSSEC transition is complete; a blocked Primary import does not silently
  create a Secondary instead. Forwarder settings and catalog-specific properties
  must be configured separately.

### Convert a Secondary to Primary

- **Convert to Primary Zone** moves write ownership of an independent, unsigned
  Secondary to Sable without deleting and recreating the zone. Zone identity,
  records, permissions, and revision history are retained. Conversion is available
  in the console and API.
- Review the source servers, SOA serial, and record count, confirm the source
  write freeze, and synchronize once more before converting. A failed final
  transfer leaves the zone Secondary. A stored-snapshot option is available when
  needed, but requires you to verify that the saved data is suitable for cutover.
- Conversion advances the SOA serial and stops upstream refresh and Secondary
  expiry tracking. Stale confirmations and late transfers cannot overwrite the
  converted Primary. Existing SOA and NS targets remain for you to review before
  retiring the source.
- DNSSEC-signed zones and members managed by a Sable catalog show why conversion
  is unavailable. Expandable DNSSEC migration guidance explains the signing
  transition; transferred public records do not include private signing keys.
  Membership in a catalog on the source server alone does not block conversion
  of an independent Sable Secondary.
- Migration dialogs use clearer status cards, warning and information alerts,
  and aligned confirmation controls. When conversion is unavailable, the dialog
  offers **Close** instead of a disabled conversion button.

### Cluster visibility

- Zone lists and detail pages identify the catalog managing each zone, with a
  link to the catalog on the detail page.
- **Rolling Updates** remains visible when a clustered installation cannot use
  it. A warning explains the blocking condition, and unavailable update actions
  are hidden. Docker guidance clarifies that automatic restart requires both
  `SABLE_WEB_UPDATES=true` and `updates.restart_managed=true`, plus a working
  container restart policy.
- Cluster IDs use the available space and wrap instead of being truncated early.
- Updated timestamps and node uptime animate changing digits in place, with
  fixed-width digits and consistent lowercase time units. Reduced-motion
  preferences are respected.

### Console polish

- The Sable logo uses a black background behind the gold **S** in light mode for
  stronger contrast, without an extra black outline around the badge.
- Delete buttons for blocked and allowed entries remain visible without hovering,
  making them easier to find and use on touchscreens.
- Dashboard stat text uses darker shadows matched to each tile's color.
- About, Support, and Metrics headings use consistent icons in the logo's gold.

### Migration documentation and demo

- A Technitium migration guide covers inventory, transfer staging, catalog import,
  ownership cutover, DNSSEC transitions, verification, and rollback planning.
- A disposable migration lab runs a real Technitium container alongside a
  three-node Sable cluster. It includes standalone, catalog-managed, and signed
  zone examples for trying the workflow before a production migration.

## [1.1.0] - 2026-09-11

### Updates

- The console checks for releases after sign-in by default and shows a dismissible
  notification with release notes. Turn checks off for this node in Settings → General.
- About displays notes from the GitHub release, and installed versions on About
  and Cluster link to their release pages.
- Notifications let you install this node or update the entire cluster and
  remember your last choice in this browser. Installation progress and the
  restart action stay in the notification, with confirmation after an update.
- Release notes remain available after restarting, including while offline.
- Cluster can update all nodes to one reviewed release, restarting replicas one
  at a time and waiting for their running version and synchronization before
  updating the primary. Progress survives the primary's final restart. Failures,
  timeouts, or an operator stop prevent further restarts.
- Rolling updates require support and automatic restart on every node. Older
  nodes need a manual upgrade first. DNS clients must use multiple nodes to
  maintain service during a restart.
- Publishing now requires curated notes for every release, including candidates;
  merge commits and raw commit lists no longer become user-facing notes.

## [1.0.2] - 2026-09-10

This patch release keeps live console updates from interrupting keyboard
navigation and makes block-list downloads easier to follow.

### Console interaction

- Dashboard stat cards and scope controls retain keyboard focus through live
  updates. Automatically refreshed panels also preserve open controls and
  unsaved form edits, including backup settings.
- Routine dashboard refreshes keep the chart at full brightness. Loading
  feedback appears when changing the chart range or overview scope. Stat cards
  update in place so their focus and hover highlights do not pulse.
- Query logs discard in-flight refreshes after pausing live updates or changing
  filters, so an older response cannot replace the selected view.
- About shows a seven-character commit SHA on mobile while retaining the full
  SHA on larger screens and in the tooltip.

### Block-list feedback

- Adding a catalog or custom block list shows a compact loading spinner and
  prevents duplicate submissions while the download and compilation finish.
  The dialog stays in place, and mobile Add buttons keep their visible icons.
- Manual add and update failures show error toasts. Connection interruptions
  and unrendered HTTP errors now show a dismissible notice, including inside
  the open Add dialog, without clearing the custom URL.

## [1.0.1] - 2026-09-10

This patch release fixes block-list setup, improves the mobile console, and
protects development builds from being replaced by published releases.

### Block lists and Docker

- Hagezi Pro now uses its working AdBlock feed. Existing subscriptions to the
  retired URL migrate automatically while retaining their cached blocking data.
- The block-list catalog uses consistently aligned Add and Added controls,
  removes duplicate badges, and uses compact icon buttons on mobile.
- A ready-to-use Docker Compose configuration and updated installation examples
  give the container independent DNS for downloads and startup. DNS lookup
  failures now include clearer guidance for Docker deployments.

### Console and updates

- Development and snapshot builds disable release checks and self-update
  installation in both the console and CLI. Development containers also keep
  running their image's build instead of selecting a staged release.
- About combines installation details and update controls in one section,
  groups support links together, and shows a readable build date and time using
  the browser's timezone and 12/24-hour preference. Development builds have a
  distinct striped status panel with improved mobile spacing.
- The Go toolchain is updated to 1.27.1, with dependencies updated to their
  latest stable releases, including PostgreSQL, QUIC, SQLite, cryptography,
  networking, and the vulnerability scanner.

## [1.0.0] - 2026-09-06

The first stable release brings together Sable's authoritative and recursive
DNS service, cluster administration, query visibility, and operating tools.

### Query visibility and dashboard scale

- Query rows now open a detail drawer that explains the blocking policy, cache,
  resolver, route, and DNSSEC decisions recorded for that request, with direct
  policy actions where appropriate.
- Cursor-based history browsing replaces deep offsets, and per-minute rollups
  keep selected-range rankings and dashboard insights exact without repeatedly
  scanning the retained raw log.
- Dashboard overview cards can show local-process or cluster scope, remember the
  operator's choice, and link to query history with matching time filters.
- DNS response latency is exported as a bounded-cardinality Prometheus
  histogram partitioned by source, protocol, cache result, and response code.

### Zones and integrations

- The zone Change Center exposes retained revisions, visual diffs, and rollback.
  A rollback creates a new revision, advances the SOA serial, and uses the full
  validation, persistence, activation, journaling, and NOTIFY path.
- Primary-zone changes and RFC 2136 updates maintain a bounded IXFR journal with
  AXFR fallback when the requested history is unavailable.
- UniFi synchronization now owns A, AAAA, and matching IPv4 and IPv6 PTR records
  without disturbing hand-authored records.
- Dynamic DNS can discover public IPv4 and IPv6 addresses and reconcile
  external A/AAAA RRsets across multiple zones and providers through the same
  nine adapters used by ACME DNS-01. Provider credentials are shared securely
  and replicated for cluster takeover.
- Record validation rejects changes that would leave a CNAME sharing its owner
  name with incompatible data.

### Clustering and encrypted DNS

- The DNS client can target an enrolled cluster member through that node's
  advertised DoH endpoint and reuse the certificate authority pinned during
  enrollment.
- Cluster links, live status updates, generation visibility, and planned
  handoff feedback were refined for day-to-day operation.
- Forwarding over DNS-over-QUIC now reuses persistent upstream connections, and
  local console DoH queries use the correct endpoint and trust path.

### Console, performance, and delivery

- The server-rendered console now uses vendored htmx 4 with an explicit fragment
  response contract and idempotent helper initialization.
- Embedded web assets use content fingerprints, long-lived immutable caching,
  and precompressed variants.
- Resolver hot-path allocation work, repeatable latency benchmarks, and occupied
  benchmark-port detection improve performance confidence and diagnostics.
- Backup completion notices remain visible through fast restore and redirect
  paths.
- Closed mobile navigation no longer creates invisible keyboard stops, and
  dashboard metric links expose their current values and details to screen
  readers, including after live updates.
- Metric cards and query-chart series share the same bright category colors
  in both themes. White labels use soft shadows, and loading effects no longer
  obscure or fade the text.

### Release and security operations

- Recursive answers and cached recursive data default to private clients, with
  explicit allow, deny, and IP/CIDR access-list modes across DNS transports.
  Public authoritative service remains available, and queries with recursion
  disabled do not trigger ordinary upstream lookups.
- Configurable global and per-client limits bound unresolved DNS work,
  including duplicate waiters and background refreshes. Excess work is refused
  promptly and counted in metrics while cached and authoritative answers remain
  available.
- SSO trust, provisioning, and role-mapping changes require user-administration
  permission. Retained zone history is authorized against each snapshot's zone
  identity, protecting records from earlier owners of a recreated zone name.
- Systemd and Docker deployments can explicitly opt into verified console
  updates while Sable remains non-root and unable to write the system path or
  access the Docker socket.
- The gated GitHub Actions release workflow validates protected `main`, creates
  an annotated semantic-version tag, publishes checksummed cross-platform
  archives and multi-architecture containers as a replaceable draft, and makes
  the release visible only after every artifact succeeds.
- Automated quality, release-artifact, race, smoke, and reachable-dependency
  vulnerability checks protect the release path.
- `SECURITY.md` documents supported versions and private vulnerability
  reporting.

### Known boundaries

- The bright metric cards retain white text with soft shadows. Rendered contrast
  falls below WCAG AA thresholds in parts of these cards; this release does not
  claim full WCAG conformance.
- A cluster continues answering DNS when its primary is unavailable, but
  control-plane failover remains a manual operator action. Sable does not yet
  claim quorum-based or partition-safe automatic failover.
- Browser sessions, audit history, token-use timestamps, caches, listener and
  certificate configuration, database paths, and security bootstrap remain
  node-local rather than replicated state.
- OpenTelemetry export, cluster-wide telemetry aggregation, published encrypted
  transport capacity profiles, and broader fault-injection and cross-version
  recovery suites remain roadmap work.
