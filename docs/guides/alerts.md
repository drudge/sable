# Get alerts

Sable can tell you about what it notices wherever you look: on your phone through ntfy or Pushover, in a Slack or Discord channel, through a webhook, or as a notification in your browser. Set it up in **Settings > Alerts**.

## Before you begin

Anyone who can read settings can see the Alerts tab. Changing it needs permission to change settings. On a cluster, make changes on the primary; only the node leading the cluster sends alerts, so each one arrives once.

## Add a destination

Select **Add Destination**, give it a name if you like, such as "Phone", and pick its format:

- **Webhook** posts JSON to a URL, which works with Home Assistant and anything else that takes a JSON POST. Its `text` and `content` fields also make a plain Slack or Discord message.
- **ntfy** posts plain text with a title to your topic's URL, which ntfy shows as a notification.
- **Slack** posts to an incoming webhook as a card: the alert, its reasons, a colored bar for how much it matters, and a button back to Sable.
- **Discord** posts to a channel webhook as an embed colored by how much the alert matters. It never mentions anyone.
- **Pushover** asks only for your application token and user key; Sable knows Pushover's address.
- **Browsers** shows each alert as a notification in the browsers that turn alerts on. See [Browsers](#browsers).

**Sends** picks what the destination gets: **Everything**, or **Only These Types**. You might send everything to a Slack channel and only cluster problems and failed sign-ins to your phone.

Use **Preview** to see exactly what Sable would send before you save, and **Copy** in its corner to take it with you. URL tokens, keys, and header values are cut short.

For a webhook or ntfy, open **Advanced** for two more options:

- **Check for an ntfy Receipt** only counts a send when ntfy answers with a message ID. Without it, any server that answers counts, so a typo like `nfty.sh` can look like it worked.
- **Headers** are sent with every alert. Use `Authorization` to reach a protected ntfy topic, or `Priority` and `Tags` to change how the notification looks.

When you add a destination, Sable takes stock of what is already news without sending it, so you are not flooded with old alerts. From then on, each alert goes to it once.

## Secrets stay secret

A webhook URL usually carries a token, and Pushover keys and header values are credentials. Sable keeps them in its encrypted vault, not in `sable.toml`, and never shows them again. When you edit a destination, each saved one shows cut short, such as `Saved: https://ntfy.sh/••••erts`. Leave a field blank to keep what is saved, or type a new value to replace it.

Removing a destination forgets its secrets too.

## Check that it works

Use **Send Test** on a destination to send it a sample alert. Sable says what the service answered: the message ID ntfy published, the request Pushover accepted, or why Slack, Discord, or Pushover refused it. For Slack, Discord, and Pushover, Sable also checks that the service itself answered, so a mistyped URL shows an error instead of looking like it worked.

Each destination in the list shows its last send, or its last error, since Sable started. A destination that fails does not hold up the others.

## Choose which alerts Sable sends

**Alert Types** turns whole kinds of alerts on or off for every destination. Select **Save Alert Types** after a change.

- **Insights Findings** are new findings worth a look. Anything you hid in Insights is skipped. Each kind of finding, such as a new device on the network, has its own switch under it; turning one off keeps that kind in Insights without alerts. Limits live in Insights Settings.
- **Cluster** is a node going down and coming back up, and update rollouts.
- **Sable Updates** is a new release of Sable.
- **Integrations** is UniFi sync and dynamic DNS.
- **Backups** sends **Failures Only**, **Every Backup**, or nothing when **Off**.
- **Server Health** is certificate renewals, secondary zones, and DNSSEC keys.
- **Domain Watches** is a device looking up a domain you picked. See [Watch domains](#watch-domains).
- **Failed Sign-Ins** is off unless you turn it on. Sable sends one alert when a node sees as many failed sign-ins as you set within the minutes you set, 5 within 10 to start.

Problems, such as a node going down or a backup failing, go out at high priority on ntfy, Pushover, and browsers.

## Watch domains

A watch alerts when a device looks up a domain you pick, such as a game on a child's tablet or a site you know is bad. Select **Add Watch** under **Watches**:

- **Domains** are one per line. Names under each one count too, so `discord.com` also covers `gateway.discord.com`, as blocking rules do.
- **Devices** is **Any Device**, or **Only These Devices**: pick them from the devices Insights knows, or type addresses and networks such as `10.0.7.20` or `10.0.7.0/24`. A device picked from the list is followed across address changes. With Insights off, Sable keeps no devices, so watches pick them by address and network only.
- **When** alerts on lookups that were **Allowed or Blocked**, **Only When Allowed**, or **Only When Blocked**.
- **Quiet For** is how long the same device stays quiet for that watch after an alert: 15 minutes, 1 hour (the default), 6 hours, or 24 hours.

The alert names the watch and the device, the names it looked up, how many times, and whether blocking stopped them, with a button that opens those lookups in Query Logs. Each row in **Watches** has a switch to turn it off without removing it, and says when it last alerted.

The fastest way to start one is **Watch** in a query's details in Query Logs, or the eye beside a domain in a device's details in Insights. Either opens **Add Watch** with the domain and the device filled in.

Sable checks the query log for new lookups about once a minute, away from answering DNS, so watches never slow a lookup down. They need the query log on. In a cluster, every node checks its own lookups and the lead weighs them together, so a device that asks two nodes still alerts once. A lookup seen only by a replica takes a minute or two longer.

## Pause alerts

Use **Pause** to stop every alert without forgetting where they go, and **Resume** to start them again. Alerts that come up while alerts are paused are not sent when you resume. **Send Test** still works while paused. Pause shows only while alerts are on: with no destination able to send, there is nothing to pause.

The top of the tab says whether alerts are **On**, **Paused**, or **Off**. On means they are not paused and at least one destination can send. The bell beside the range control in Insights says whether Insights findings go out, and opens this tab.

## Browsers

Add **Browsers** as a destination. Its row then has **Turn On in This Browser**: select it and allow notifications when your browser asks. Alerts then show up even when Sable is closed. The row lists every browser that turned alerts on, and **Remove** beside one stops it. Removing the Browsers destination stops them all and forgets them.

No account or app is needed: Sable signs each push with its own key, and your browser's push service delivers it. Browsers allow this only when Sable is opened over HTTPS, or at `localhost`, and on iPhone and iPad only after Sable is added to the Home Screen. The Sable server needs to reach the internet to hand pushes to those services.

You can also set up alerts in `sable.toml`; see [Alerts](../configuration.md#alerts).
