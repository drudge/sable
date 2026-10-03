package pages

import (
	"github.com/a-h/templ"

	"github.com/drudge/sable/internal/web/pages/components"
)

// Icon draws a console icon. It lives in the components package; this keeps
// the many @Icon calls in this package short.
func Icon(kind string) templ.Component { return components.Icon(kind) }
