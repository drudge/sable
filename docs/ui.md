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
use htmx plus small dependency-free JavaScript helpers, and assets are embedded
with `go:embed`. There is no Node.js runtime or separately deployed frontend.

Visual changes should be checked at desktop, tablet, and phone widths against
the corresponding Isotope screen before they are considered complete.
