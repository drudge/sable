# Accessibility and keyboard control

Accessibility is a product requirement for the Sable console, not a finishing
pass. New and changed features must support keyboard and assistive-technology
users with the same information, controls, and outcomes available to pointer
users. Sable targets WCAG 2.2 Level AA.

## Product goals

- Every feature is operable with a keyboard alone, without timing-dependent or
  pointer-only steps.
- Navigation, main content, dialogs, notifications, and live data are exposed
  through meaningful landmarks, names, roles, and states.
- Focus is always visible and predictable. Opening, updating, and closing UI
  must not strand focus or move it without a user-understandable reason.
- Authorization, loading, empty, error, and disabled states remain
  understandable without relying on color, position, or animation alone.
- Desktop, compact, and mobile layouts preserve the same keyboard reachability
  and reading order.

Conformance is the baseline. When a standard pattern would make an operational
workflow unnecessarily slow, Sable should add an efficient shortcut while
retaining the standard interaction.

## Keyboard interaction model

### Page navigation

- The first focusable controls on authenticated pages are visible-on-focus skip
  links to primary navigation and main content.
- The navigation and main-content landmarks have stable programmatic targets.
  The current page is identified with `aria-current="page"`.
- DOM order follows the visual and reading order. Do not use positive
  `tabindex` values to repair an incorrect structure.
- Sidebar and mobile navigation disclose their expanded state. An open mobile
  drawer contains focus, makes background content inert, closes with Escape,
  and returns focus to its trigger.

### Controls and composite widgets

- Prefer native links, buttons, inputs, selects, details, and dialogs. A styled
  element must not imitate a native control unless the native element cannot
  express the interaction.
- Tab moves between controls. Arrow keys operate a composite control such as a
  tab list, radio group, menu, listbox, or data-chart cursor. Home and End move
  to the first and last item where that convention applies.
- Tab lists use one tab stop, connect every tab to its panel, and expose the
  selected state. Selecting a shareable tab also produces a meaningful URL.
- Icon-only controls have explicit accessible names. Disabled controls explain
  why the action is unavailable when that reason is useful to the operator.
- A table row, hover state, gesture, or drag operation is never the only route
  to an action.

### Focus and dialogs

- Focus indicators must remain visible in light, dark, high-contrast, and
  forced-colors modes. Do not remove an outline without providing an equally
  visible replacement.
- Opening a dialog puts focus on its first useful control or on the dialog
  heading when reading context is needed first. Dialogs are named, contain
  focus, close with Escape when safe, and restore focus to their invoker.
- After a user-requested update, focus stays on the initiating control or moves
  to the resulting content or next required control. Re-rendered fragments
  must not reset focus to the document body.
- Destructive or consequential actions use confirmation appropriate to their
  risk; focus begins on the safe choice unless immediate text entry is needed.

### Search, commands, and shortcuts

- Command-K on macOS and Control-K elsewhere opens the command palette. Escape
  closes it and restores focus. Arrow keys, Home, and End move through results;
  Enter runs the selected result.
- Palette commands are permission-aware and grouped by purpose. Scoped search
  accepts its term and any search mode in the palette before opening filtered
  results.
- Global shortcuts must not activate while the user is composing text, except
  for the documented palette shortcut. Shortcuts supplement normal controls;
  they never replace them.
- Search and filter controls have persistent labels or accessible names and
  announce result counts after filtering.

### Logs, live regions, and asynchronous updates

- Server and query logs are named, focusable reading regions with
  keyboard-reachable row details and actions at every responsive width.
- Polling pauses while focus is within a log region so content being read or
  operated cannot be replaced. Resuming updates must not discard the user's
  place without notice.
- User-triggered successes and status changes are announced with a polite
  status region. Errors that require attention use an alert. Toasts are not the
  only place durable or actionable information appears.
- Busy controls expose their state and prevent duplicate submission. Background
  progress has a named status, and completion leaves a meaningful focus target.

## Visual and motion requirements

- Text, controls, focus indicators, charts, and status colors must meet the
  applicable WCAG 2.2 AA contrast requirements.
- Information is never encoded by color alone. Charts and SVG summaries expose
  equivalent names and exact keyboard-readable values.
- Content supports browser zoom and text reflow without loss of controls or
  meaning. Touch targets should meet the WCAG 2.2 target-size minimum.
- Respect `prefers-reduced-motion`; nonessential motion is removed rather than
  merely shortened.

## Definition of done

For every new or materially changed interaction:

1. Complete its primary, error, and recovery paths using only Tab, Shift-Tab,
   Enter, Space, Escape, and the documented arrow-key conventions.
2. Verify skip links, navigation-to-main movement, focus order, visible focus,
   dialog entry and return, and focus after htmx updates.
3. Inspect accessible names, roles, states, relationships, headings, landmarks,
   table captions, and live announcements with browser accessibility tools.
4. Exercise the feature at desktop, tablet, and phone widths, at 200% zoom,
   with reduced motion, and in forced-colors or a high-contrast mode.
5. Test dynamic surfaces such as logs with polling both active and paused by
   focus. Confirm that refreshed content does not interrupt keyboard use.
6. Add focused automated coverage for semantics or behavior that can regress,
   and manually test the interaction in a real browser. A screenshot alone is
   not accessibility verification.

An accessibility regression has the same release priority as a functional
regression. If a feature cannot meet this contract immediately, document the
gap and provide an equivalent accessible path before shipping it.
