package pages

import (
	"github.com/a-h/templ"

	webassets "github.com/drudge/sable/internal/web/assets"
)

func assetURL(name string) templ.SafeURL {
	return templ.URL(webassets.URL(name))
}
