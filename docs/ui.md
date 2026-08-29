# Sable UI

Sable's web console is a native Go/templ port of Isotope. Isotope is the
design source of truth, not a loose visual reference.

## Fidelity contract

New screens and components must preserve Isotope's:

- information architecture and navigation order;
- responsive 256px sidebar and compact/mobile states;
- shadcn surface, text, border, input, and radius tokens;
- 4px spacing scale and established page/card density;
- typography hierarchy and monospace treatment of DNS data;
- Lucide icon language, colored metric cards, and bordered depth model;
- light, dark, and system theme behavior;
- hover, focus, loading, empty, error, and disabled states.

Only product identity, backend-specific terminology, and controls unsupported
by Sable may differ. Unsupported destinations remain visibly disabled until
their native Sable backend exists; they must not be redesigned or silently
removed.

## Implementation constraints

The console is compiled into the Sable binary. Pages use templ, interactions
use vendored htmx 4 plus small dependency-free JavaScript helpers, and assets
are embedded with `go:embed`. There is no Node.js runtime or separately
deployed frontend. Every asset URL contains a content fingerprint; immutable
assets are served precompressed when the browser accepts gzip.

The application helper is registered before htmx initializes. It adds CSRF
headers, initializes controls in the original document and later fragments,
and owns behavior that should not be encoded as server state: themes, sidebar
preference, routed dialogs, confirmation dialogs, range pickers, tabs, upload
progress, and small visual transitions. A helper must be safe to run more than
once because htmx can process a newly swapped subtree at any time.

### Fragment contract

- Page routes render complete documents. `/ui/` routes render the smallest
  complete fragment that owns the state being changed.
- Successful mutations return a rendered replacement, a no-content response,
  or an `HX-Redirect`/`HX-Replace-Url` instruction. They do not ask client code
  to recreate server-owned markup.
- htmx 4 swaps error responses by default. Sable admits a non-2xx body into a
  target only when the server marks it with
  `X-Sable-Console-Fragment: true`; bare server and proxy errors remain outside
  the page instead of replacing a form with arbitrary text.
- Long-running backup, update, certificate, and cluster operations own their
  busy state and polling surface. Buttons use `hx-disable` or an equivalent
  local guard so a repeated click cannot start the same operation twice.
- A replica renders primary-only controls as unavailable while keeping
  node-local actions such as DNS queries, cache operations, certificate work,
  session revocation, cluster leave, and recovery promotion available.

### Interaction and navigation contract

- Native `<dialog>` elements provide focus containment and escape behavior.
  `data-dialog-open`, `data-dialog-close`, and `data-dialog-url` connect buttons,
  routed URLs, history state, and deep links without duplicating dialog logic.
- Local tab strips support arrow-key navigation, update the relevant document
  title, and preserve a meaningful URL when the selected tab is shareable.
- Dashboard chart range, ranking, and query-log links must describe the same
  time window. Exact ranked values must not broaden into substring filters.
- Query detail rows expose persisted policy, cache, resolver, route, and DNSSEC
  decisions. Policy shortcuts remain permission-aware and retain a usable
  mobile disclosure control.
- The zone Change Center shows bounded diffs and describes rollback as creating
  a new revision; the UI must never imply that durable history is rewritten.
- Cluster node links open the member's advertised console. DNS client presets
  may use the member's pinned certificate authority for DoH but must never
  disable TLS verification globally.

### Accessibility and responsive verification

The complete product goals, keyboard interaction model, and definition of done
live in [Accessibility and keyboard control](accessibility.md). The requirements
below summarize the console-specific behaviors that implementations must
preserve.

Interactive work is not complete until it has keyboard focus treatment, an
accessible name, a useful disabled reason, a reduced-motion behavior where
animation is nonessential, and a live-region or status treatment for background
progress. Controls removed by authorization should not leave empty navigation
groups or keyboard stops.

The console treats keyboard and assistive-technology access as a product
contract:

- Every authenticated page starts with visible-on-focus links to the primary
  navigation and main content. Those landmarks are programmatically focusable,
  and the active navigation link exposes `aria-current="page"`.
- Desktop and mobile navigation keep their expanded state synchronized. The
  mobile drawer moves focus into navigation, makes main content inert, traps
  focus while open, and returns focus to its trigger when Escape closes it.
- Tab lists use one tab stop. Arrow keys, Home, and End move and activate tabs;
  every tab names a corresponding tab panel.
- Native dialogs have an accessible name, put focus on the first useful field,
  and return focus to the invoking control. A whole table row is never the only
  way to reach an action.
- Runtime and query logs expose named, focusable reading regions. Live polling
  pauses while focus is inside a log panel so a refresh cannot replace content
  that somebody is reading or operating, and row detail actions remain visible
  and keyboard reachable at desktop and mobile widths.
- htmx updates preserve a meaningful focus target and announce user-requested
  changes. Filters announce result counts, while errors and background status
  use the appropriate alert or live-region behavior.
- The global command palette opens with Command-K on macOS or Control-K on
  other platforms. It groups authorized pages, zones, search actions,
  integrations, and quick actions separately; supports ranked fuzzy search
  plus Arrow/Home/End navigation; provides one-step operational commands such
  as timed blocking pauses; and keeps server-log, query-log, DNS-cache,
  blocking-policy, and per-zone record search terms in the palette before
  opening the filtered destination. Query-log search can target either a
  domain or client IP, with Left/Right switching that mode while focus remains
  in the palette input. Page, dialog, and confirmation commands hand focus to
  the control that is ready for input. Cluster quick actions reflect whether
  the current writable node is standalone or the primary.
- Canvas and SVG summaries provide keyboard-readable values. The query chart
  supports sample-by-sample arrow navigation, and distribution legends expose
  exact values and percentages as a list.
- Tables provide captions, icon-only controls provide explicit names, and
  reduced-motion and forced-colors preferences receive dedicated styling.

Visual changes should be checked at desktop, tablet, and phone widths against
the corresponding Isotope screen before they are considered complete. Run
`mage screenshots` for the deterministic desktop fixture, then manually exercise
dialogs, forms, tabs, filters, error responses, and mobile disclosures in a real
browser; screenshot capture proves rendering, not interaction behavior.
