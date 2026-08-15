package web

import (
	"net/http"
	"strings"
	"time"

	// The embedded timezone database keeps browser zone names resolvable on
	// hosts without tzdata installed, such as the distroless container image.
	_ "time/tzdata"

	"github.com/drudge/sable/internal/web/pages"
)

const (
	timeFormatCookie   = "sable_time_format"
	timeZoneCookie     = "sable_time_zone"
	maximumZoneNameLen = 64
)

func requestTimeDisplay(request *http.Request) pages.TimeDisplay {
	return pages.TimeDisplay{Format: requestTimeFormat(request), Location: requestTimeLocation(request)}
}

func requestTimeFormat(request *http.Request) string {
	cookie, err := request.Cookie(timeFormatCookie)
	if err == nil && cookie.Value == pages.TimeFormat24 {
		return pages.TimeFormat24
	}
	return pages.TimeFormat12
}

// requestTimeLocation resolves the browser's timezone so console timestamps
// match the operator's clock. Servers commonly run in UTC, so falling back to
// the process location is a last resort rather than the default.
func requestTimeLocation(request *http.Request) *time.Location {
	cookie, err := request.Cookie(timeZoneCookie)
	if err != nil || !validZoneName(cookie.Value) {
		return time.Local
	}
	location, err := time.LoadLocation(cookie.Value)
	if err != nil {
		return time.Local
	}
	return location
}

func validZoneName(name string) bool {
	if name == "" || name == "Local" || len(name) > maximumZoneNameLen {
		return false
	}
	if strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
		return false
	}
	for _, character := range name {
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9',
			character == '/', character == '_', character == '-', character == '+':
		default:
			return false
		}
	}
	return true
}
