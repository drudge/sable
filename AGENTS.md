# AGENTS.md

Sable is a DNS server written in Go. One static binary holds the DNS server, the admin API, the MCP server, and the web console. This file is for AI coding agents. People should start with [README.md](README.md) and [docs/](docs/index.md).

## Before you start

- Branch from the latest `origin/main`, not a local `main`. Local branches go stale quickly.
- If the work comes from an issue, read the issue first. If it has a **Decisions** comment, those answers are final. If you think an approved design should change, say so and wait for an answer before building something different.
- Before writing a new script or tool, search `scripts/` and the mage targets for one that already does the job. Extend it instead of adding a second one.

## Where things live

| Path | What it holds |
| --- | --- |
| `cmd/sable` | The binary's entry point |
| `internal/dnsserver` | The DNS data plane: query handling, cache, and the blocking decision |
| `internal/web` | HTTP server, console handlers, JSON API, and the MCP server (`mcp*.go`) |
| `internal/web/pages` | Console components in templ (`*.templ`) and their generated `*_templ.go` |
| `internal/web/assets` | `app.js`, `app.css`, vendored htmx, and fonts, embedded and fingerprinted |
| `internal/config` | The TOML configuration and its validation |
| `internal/store` | SQLite and PostgreSQL storage |
| `internal/insights` | Insights findings, with `devices` and `blocking` analyzers |
| `internal/alerts`, `internal/cluster`, `internal/unifi`, `internal/dynamicdns`, `internal/update` | The features their names say |
| `scripts/demo` | The Vandelay Industries demo: three nodes, a mock UniFi controller, and 30 days of traffic |
| `scripts/browser` | Playwright browser tests and the screenshot engine (`screenshots.cjs`) |
| `docs/` | Architecture, UI and accessibility contracts, configuration, guides, API reference, and releasing |

Read [docs/architecture.md](docs/architecture.md) before changing how the parts fit together.

## Build and check

Use the mage targets. They set `GOEXPERIMENT=jsonv2`, so set it yourself when you run `go` directly.

| Command | What it does |
| --- | --- |
| `go tool mage build` | Builds `bin/sable` |
| `go tool mage generate` | Regenerates templ components and third-party notices |
| `go tool templ generate -path internal/web/pages` | Regenerates templ components only |
| `go tool mage verify` | Checks generated files, runs every test, and runs `go vet` |
| `go tool mage race` | Runs the tests with the race detector |
| `go tool mage bench` | Runs the DNS, storage, and blocking benchmarks |
| `go tool mage devDemo` | Runs the Vandelay demo with hot reload; open http://localhost:5381 |
| `go tool mage dev` | Runs one server from your own `sable.toml` with hot reload; open http://localhost:5381 |

Before every push, run `go tool mage verify` and `gofmt -l .`. `gofmt -l .` must print nothing. `verify` doesn't check formatting, but CI does.

Never edit a `*_templ.go` file by hand. Change the `.templ` file, regenerate, and commit both.

CI runs four checks on every PR:
- **Quality:** formatting, `go mod tidy`, `mage verify`, and `govulncheck`
- **Race detector**
- **Browser regression**
- **Release artifacts**

### Browser tests

Each `TestBrowser…` test in `internal/web/*_browser_test.go` serves Go fixtures and drives a script in `scripts/browser/`. On a Mac with Chrome installed:

```sh
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci --prefix scripts/browser
SABLE_TEST_BROWSER="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  GOEXPERIMENT=jsonv2 go test -count=1 -tags=browser -run TestBrowser ./internal/web
```

Elsewhere, run `scripts/browser/node_modules/.bin/playwright install chromium` and leave `SABLE_TEST_BROWSER` unset.

A browser test must pass on a slow CI machine too. Wait for the request or state it depends on, never a fixed delay. For example, a test that hides something and then opens a link waits for the hide request to finish first.

## The Vandelay demo

Check UI work in the demo, not in a custom seed.
- `go tool mage devDemo` runs the demo under Air, which gives you hot reload. Saving a `.go`, `.templ`, `.css`, or `.js` file regenerates the templ components, rebuilds, and restarts the demo with its data kept.
- Open http://localhost:5381, Air's proxy in front of the demo, and the page reloads itself after each rebuild. The demo answers directly at http://localhost:5391, but there you reload by hand.
- A rebuild can take up to a minute, so finish a batch of edits before you look.
- The reload works because mage hands the demo the hash of Air's reload script, and the console's Content Security Policy lets that one inline script run. Any other inline script is still blocked, just as in production.
- The demo signs you in on its own. Stay on `localhost`; `127.0.0.1` shows the sign-in page because the cookie is per host.
- `go tool mage dev` does the same for a single server using your own `sable.toml`, which isn't in the repository. Air expects that server on port 5380. Both targets use port 5381 for the proxy, so run only one at a time.
- The demo uses ports 5381, 5391-5393, 5491-5493, and 8555-8557. If another demo already holds them, don't stop it. Run yours on other ports instead:
  1. Change `8555+index` in `scripts/demo/main.go` to another range.
  2. Pass `-base-port`.
  3. Revert the file.
- When you're done, leave your demo or preview running so the user can click around.

## The web console

The console is server-rendered templ with vendored htmx 4 and small, dependency-free helpers in `app.js`. There is no Node runtime, bundler, or frontend framework. [docs/ui.md](docs/ui.md) and [docs/accessibility.md](docs/accessibility.md) are the contracts; read them before UI work.

- The Content Security Policy is `script-src 'self'` and `style-src 'self'`. That rules out inline `<script>`, `<style>`, `style=""` attributes, and `eval`. Behavior goes in `app.js` and styles in `app.css`. Script may still set `element.style`.
- htmx can process a swapped fragment at any time, so every `app.js` helper must be safe to run more than once. Content can also arrive without an htmx swap, so watch the page for added elements rather than only listening for htmx events.
- `internal/web/assets/assets_test.go` pins some exact CSS and JS text. When you change one of those rules on purpose, update the test with it.

### Design quality

Every screen should look finished: polished, responsive, and consistent with the rest of the console. A new screen should look like it was always there.

- **Follow the design system.** Isotope is the source of truth ([docs/ui.md](docs/ui.md)). Use its tokens in `app.css` (`--background`, `--card`, `--muted`, `--border`, `--ring`, and the rest) rather than hard-coded colors, along with the 4px spacing scale, the existing type sizes, and Lucide icons. Set DNS data such as names and addresses in monospace.
- **Reuse before you build.** Start from the closest existing screen and copy its structure, spacing, copy style, and states. Use the shared templ components before writing markup:
  - `SettingsCard`, `SettingsSaveButton`
  - `DetailDrawer`, `DetailDrawerContent`
  - `StatCard`, `RankedPanel`
  - `SearchField`, `Toast`, `UpdateIndicator`
  - `CopyButton`, `CopyLinkButton`, `ScrollFadeHint`, `Icon`

  Use the shared classes too: `.button` (with `outline`, `compact`, and `destructive`), `.card`, `.status-badge`, `.count-badge`, and `.field-help`.

  If a pattern shows up twice, make it a component and use it in both places. Add a parameter to a shared component instead of copying its markup.
- **Give every control all its states:** hover, visible keyboard focus, pressed, disabled, and loading.
  - A first load shows a skeleton shaped like the content, like `RankedPanelSkeleton`.
  - A refresh shows `UpdateIndicator`.
  - A button whose request is running is disabled (`hx-disable`) and shows a pending label, such as **Saving…**.
- **Handle empty and error states.** An empty state says in one line why it's empty, like the Insights "Nothing needs your attention" card. An error says what went wrong and what to do next.
- **Keep motion subtle.** Hover effects and state changes are quick transitions of about 150ms ease, matching the existing rules. Motion should explain a change, not decorate. Under `prefers-reduced-motion`, remove motion that isn't essential.
- **Balance the layout.** Align to the 4px grid, keep rows from feeling cramped, and keep one clear primary action per area.
- **Make it responsive.** Check every screen at 1218×787 (laptop) and 390×844 (phone), in light and dark, with no sideways scrolling. Safari lays some things out differently from Chrome, so check it for layout changes.

### Console conventions

- **Help text:** one short sentence about one thing.
- **Dependent controls:** a control that only matters while a switch is on is hidden while it's off (use CSS `:has()`), not dimmed.
- **Buttons:** one job per button, with Title Case labels such as **Copy Link** and **Show Again**. A status indicator links to where its setting lives rather than opening a small dialog of its own.
- **Dialog and drawer headers** hold only the title and the close X. Actions go in the footer, or at the end of the section heading they belong to. An action that changes something gets a text label; copy and close may be icons alone.
- **Drawer footers** hold only the drawer's actions, right-aligned with the main one last. They have no Close button, since the X and Escape close a drawer, and a drawer with no actions has no footer.
- **Phone dialog footers** put the main action on top and the dismiss button at the bottom. Keep the main button last in the markup, mark the dismiss button `data-dialog-close`, and let the shared `.dialog-footer` rule do the rest.
- **Searching a long list:** the search bar goes inside the card, under its header (`.log-search-bar`), with its filters in the same bar. Keep the search and filters in the page address, and add a matching **Search** action to the command palette (`CommandSearchOption`).
- **Drawers with their own address:** reuse the routed drawers from `app.js` (`data-drawer-route`, `data-dialog-url`) and put `CopyLinkButton` in the drawer.
- **Scrolling text boxes:** mark the box `data-scroll-fade`, wrap it in `.scroll-fade-frame`, and add `ScrollFadeHint`. It fades the edge that has more to read and shows a chevron, like the sidebar.
- **Icons in flex buttons:** when CSS resizes a `.nav-icon` inside a flex button, set `flex-basis` to the same size (or `flex: none`), or Safari wraps the label.

## The DNS data plane

The query path in `internal/dnsserver` runs for every lookup. `ServeDNS` leads to `resolveRequest`, which leads to `policyDecision`.
- Keep new work off that path. Do analysis in the background, on data that's already stored.
- A change that has to touch the path must not add allocations. Show that with a benchmark (`go tool mage bench`).

## Configuration and clusters

- Configuration is decoded strictly, so an unknown key is an error. A build that doesn't know a key can't read a file that has it. Clusters mix versions during upgrades, and configuration replicates from the primary, so plan for older nodes when you add a key. Say what to do in the release notes' "Upgrading" section.
- Only the primary accepts writes. A new write path must refuse on a replica the way existing ones do (`primaryWriteControl`, and `mcpReplica` for MCP tools).

## Insights

- Findings come from stored data, never from the DNS path. A new area implements `insights.Analyzer` and returns `insights.Finding` values with a typed `Subject` and evidence (reasons and facts). Don't build one-off pages.
- Use deterministic rules. No hosted AI, and don't call Insights "AI".
- An operator's corrections, such as a device name or type, stay tied to the device's hardware address.
- While Insights is off, nothing may collect device data.
- A device-type clue lists only the hostnames the device itself talks to, never the company's website. Otherwise a laptop that visits the site gets counted as the device.

## Secrets and security

- Provider credentials, webhook URLs, and tokens live in the encrypted vault, not in `sable.toml`.
- A secret must never reach a log line, an error message, or the console. Go's HTTP client errors include the full request URL, so drop the URL when it carries a key.
- Never print API tokens, or command lines and environment variables that hold them. That includes the `mcp-remote` processes on a developer's machine.
- MCP tools check their grant inside the handler. Write tools refuse on replicas. See [docs/guides/mcp.md](docs/guides/mcp.md).

## Docs and writing

- Write docs in plain, short sentences. Name console controls in bold, as they appear: **Settings → Alerts**.
- Update the matching guide, `docs/configuration.md`, or `docs/reference/api.md` in the same PR as the change.
- Release notes live in `CHANGELOG.md`, one section per version.
  - A beta's notes may compare it with earlier betas.
  - A stable release's notes describe only the change since the last stable release. They never mention betas, commit hashes, or PR numbers, and `docs/docs_test.go` enforces that.

## Commits, pull requests, and releases

- Use one branch and one PR per feature or fix. Two changes in one PR get two commits; list them in the PR description.
- A PR that changes the console includes screenshots from the Vandelay demo. For UI that already exists, show before (`main`) and after (your branch) of the same view. For new UI, show dark and light, and a phone where it matters.
  - Take them with `scripts/browser/screenshots.cjs`: `buildDemo`, `startDemo`, `capture`, and `stopDemo`. A shot's `open(page)` can open a dialog or drawer before the picture.
  - For before shots, build from a worktree of `origin/main`, including its demo tool. A branch's demo can write configuration keys that `main` rejects.
  - Put the images on the orphan `pr-screenshots` branch, under a folder named for the PR number. Link them with `raw.githubusercontent.com` URLs pinned to that commit. Never commit screenshots to a feature branch.
- Stop at an open PR. Don't merge or release unless you're asked to.
- Releases follow [docs/releasing.md](docs/releasing.md): a `CHANGELOG.md` section in its own PR, then `release.yml` dispatched from `main`.
- `.claude/workflows/` holds saved multi-agent workflows (`feature-build.js`, `release-notes.js`). Run one only when asked for it by name.
