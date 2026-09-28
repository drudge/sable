// Package notices holds the licenses of the third-party software built into
// Sable, which many of those licenses ask to travel with it. The console
// lists them under About.
//
// notices.json is generated: go tool mage generate rewrites it from the
// modules compiled in, and go tool mage verify fails while it is out of date.
package notices

import (
	_ "embed"
	"encoding/json"
	"slices"
	"sync"
)

//go:embed notices.json
var data []byte

// A Notice is one piece of third-party software and the license files it
// asks to ship with it.
type Notice struct {
	Name string `json:"name"`
	// License is the SPDX identifier of the license that governs it.
	License string `json:"license"`
	URL     string `json:"url"`
	// Console marks the files the web console serves to browsers, as opposed
	// to what is compiled into the server.
	Console bool   `json:"console,omitempty"`
	Files   []File `json:"files"`
}

// A File is one license, notice, or patent grant, as its authors wrote it.
type File struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

var load = sync.OnceValue(func() []Notice {
	var notices []Notice
	if err := json.Unmarshal(data, &notices); err != nil {
		panic("decode third-party notices: " + err.Error())
	}
	return notices
})

// All returns every notice: the console's first, then Go, then the modules
// compiled into the server by path.
func All() []Notice {
	return slices.Clone(load())
}

// Named returns the notice for one piece of software.
func Named(name string) (Notice, bool) {
	index := slices.IndexFunc(load(), func(notice Notice) bool { return notice.Name == name })
	if index < 0 {
		return Notice{}, false
	}
	return load()[index], true
}
