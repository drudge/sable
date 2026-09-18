package web

import "net/http"

const fullRecordNamesCookie = "sable_full_record_names"

func requestShowFullRecordNames(request *http.Request) bool {
	cookie, err := request.Cookie(fullRecordNamesCookie)
	return err == nil && cookie.Value == "true"
}
