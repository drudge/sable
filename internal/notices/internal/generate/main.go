// Command generate writes notices.json: the licenses of the third-party
// software built into Sable. That is every module compiled into it on each
// platform it is released for, the Go runtime and standard library, and the
// files its web console serves from third_party.
//
// Run it from the repository root, through go tool mage generate or directly:
//
//	go run ./internal/notices/internal/generate [-check]
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// platforms are the targets a release builds. Each compiles in a slightly
// different set of modules, so the notices cover all of them.
var platforms = []string{
	"darwin/amd64", "darwin/arm64", "freebsd/amd64", "freebsd/arm64",
	"linux/amd64", "linux/arm64", "windows/amd64", "windows/arm64",
}

// consoleNotices are the files the web console serves from third_party. They
// change by hand, along with the files.
var consoleNotices = []notice{
	{Name: "htmx", License: "0BSD", URL: "https://htmx.org", Console: true, paths: []string{"third_party/htmx/LICENSE"}},
	{Name: "Inter", License: "OFL-1.1", URL: "https://rsms.me/inter/", Console: true, paths: []string{"third_party/inter/LICENSE"}},
	{Name: "Lucide", License: "ISC", URL: "https://lucide.dev", Console: true, paths: []string{"third_party/lucide/LICENSE"}},
	{Name: "Simple Icons", License: "CC0-1.0", URL: "https://simpleicons.org", Console: true, paths: []string{"third_party/simple-icons/LICENSE"}},
}

// The fields match notices.Notice, which cannot be imported here: it embeds
// the file this command writes. Versions are left out on purpose, so a
// dependency update touches the file only when a license text changes or a
// module comes or goes.
type notice struct {
	Name    string `json:"name"`
	License string `json:"license"`
	URL     string `json:"url"`
	Console bool   `json:"console,omitempty"`
	Files   []file `json:"files"`
	paths   []string
}

type file struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

var licenseFileName = regexp.MustCompile(`(?i)^(licen[cs]e|copying|notice|patents)([-._].*)?$`)

func main() {
	output := flag.String("o", "internal/notices/notices.json", "file to write")
	check := flag.Bool("check", false, "fail if the file is out of date instead of writing it")
	flag.Parse()

	generated, err := generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate third-party notices:", err)
		os.Exit(1)
	}
	if *check {
		current, err := os.ReadFile(*output)
		if err != nil || !bytes.Equal(current, generated) {
			fmt.Fprintf(os.Stderr, "%s is out of date: run go tool mage generate\n", *output)
			os.Exit(1)
		}
		return
	}
	if err := os.WriteFile(*output, generated, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write third-party notices:", err)
		os.Exit(1)
	}
}

func generate() ([]byte, error) {
	var all []notice
	for _, entry := range consoleNotices {
		for _, path := range entry.paths {
			text, err := readText(path)
			if err != nil {
				return nil, err
			}
			entry.Files = append(entry.Files, file{Name: filepath.Base(path), Text: text})
		}
		all = append(all, entry)
	}

	toolchain, err := goNotice()
	if err != nil {
		return nil, err
	}
	all = append(all, toolchain)

	modules, err := compiledModules()
	if err != nil {
		return nil, err
	}
	for _, module := range modules {
		files, err := licenseFiles(module.dir)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", module.path, err)
		}
		license, err := identify(files)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", module.path, module.version, err)
		}
		all = append(all, notice{Name: module.path, License: license, URL: "https://pkg.go.dev/" + module.path, Files: files})
	}

	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "\t")
	if err := encoder.Encode(all); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

type module struct{ path, version, dir string }

// compiledModules lists the modules that provide a package Sable compiles in
// on any release platform, sorted by path.
func compiledModules() ([]module, error) {
	found := map[string]module{}
	for _, platform := range platforms {
		goos, goarch, _ := strings.Cut(platform, "/")
		command := exec.Command("go", "list", "-deps", "-f", `{{with .Module}}{{if not .Main}}{{.Path}}{{"\t"}}{{.Version}}{{"\t"}}{{.Dir}}{{end}}{{end}}`, "./cmd/sable")
		command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0", "GOEXPERIMENT=jsonv2", "GOFLAGS=-mod=readonly")
		command.Stderr = os.Stderr
		listed, err := command.Output()
		if err != nil {
			return nil, fmt.Errorf("list %s modules: %w", platform, err)
		}
		for line := range strings.Lines(string(listed)) {
			fields := strings.Split(strings.TrimSpace(line), "\t")
			if len(fields) != 3 {
				continue
			}
			if fields[2] == "" {
				return nil, fmt.Errorf("%s %s is not in the module cache", fields[0], fields[1])
			}
			found[fields[0]] = module{path: fields[0], version: fields[1], dir: fields[2]}
		}
	}
	modules := make([]module, 0, len(found))
	for _, module := range found {
		modules = append(modules, module)
	}
	slices.SortFunc(modules, func(a, b module) int { return strings.Compare(a.path, b.path) })
	return modules, nil
}

// goNotice covers the Go runtime and standard library, which every build
// compiles in.
func goNotice() (notice, error) {
	root, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return notice{}, fmt.Errorf("find GOROOT: %w", err)
	}
	directory := strings.TrimSpace(string(root))
	files, _ := licenseFiles(directory)
	if !slices.ContainsFunc(files, func(file file) bool { return file.Name == "LICENSE" }) {
		// Some installs, such as Homebrew's, keep the license beside GOROOT.
		text, err := readText(filepath.Join(filepath.Dir(directory), "LICENSE"))
		if err != nil {
			return notice{}, fmt.Errorf("no Go license in or beside %s", directory)
		}
		files = append([]file{{Name: "LICENSE", Text: text}}, files...)
	}
	return notice{Name: "Go", License: "BSD-3-Clause", URL: "https://go.dev", Files: files}, nil
}

func licenseFiles(directory string) ([]file, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var files []file
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !licenseFileName.MatchString(entry.Name()) {
			continue
		}
		text, err := readText(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		files = append(files, file{Name: entry.Name(), Text: text})
	}
	if len(files) == 0 {
		return nil, errors.New("no license file")
	}
	return files, nil
}

func readText(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	text := strings.TrimPrefix(string(content), "\ufeff")
	return strings.TrimRight(strings.ReplaceAll(text, "\r\n", "\n"), " \t\n"), nil
}

// identify names a module's license from its text. A license it does not
// know stops the build of the notices, so a new kind gets a person's look
// before it ships.
func identify(files []file) (string, error) {
	for _, file := range files {
		text := strings.Join(strings.Fields(file.Text), " ")
		switch {
		case strings.Contains(text, "Apache License") && strings.Contains(text, "Version 2.0"):
			return "Apache-2.0", nil
		case strings.Contains(text, "Redistribution and use in source and binary forms"):
			if strings.Contains(text, "Neither the name") || strings.Contains(text, "names of its contributors") {
				return "BSD-3-Clause", nil
			}
			return "BSD-2-Clause", nil
		case strings.Contains(text, "Permission is hereby granted, free of charge"):
			return "MIT", nil
		case strings.Contains(text, "Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies"):
			return "ISC", nil
		}
	}
	return "", errors.New("unrecognized license: check it can ship with Sable, then teach identify its name")
}
