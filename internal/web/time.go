package web

import (
	"net/http"

	"github.com/drudge/sable/internal/web/pages"
)

const timeFormatCookie = "sable_time_format"

func requestTimeFormat(request *http.Request) string {
	cookie, err := request.Cookie(timeFormatCookie)
	if err == nil && cookie.Value == pages.TimeFormat24 {
		return pages.TimeFormat24
	}
	return pages.TimeFormat12
}
