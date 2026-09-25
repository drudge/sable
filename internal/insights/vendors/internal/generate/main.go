// Command generate turns the IEEE MA-L registry CSV into the compact,
// gzip-compressed table the vendors package embeds: one line per assignment,
// the six hex digits of the prefix, a tab, and the organization's short name.
//
//	curl -sSLo oui.csv https://standards-oui.ieee.org/oui/oui.csv
//	go run ./internal/insights/vendors/internal/generate -in oui.csv -out internal/insights/vendors/oui.txt.gz
package main

import (
	"compress/gzip"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"slices"
	"strings"
)

// legalSuffix matches the company-form endings that make names long without
// making them clearer, such as "Co., Ltd." or ", Inc.".
var legalSuffix = regexp.MustCompile(`(?i)[\s,.]+(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|l\.l\.c|gmbh|ag|s\.?a|s\.?p\.?a|b\.?v|n\.?v|plc|pty|oy|ab|as|srl|s\.?r\.?l|kg|kk|pte|sdn\s+bhd|bhd|co\.?,?\s*ltd)\.?$`)

func main() {
	input := flag.String("in", "oui.csv", "IEEE MA-L registry CSV")
	output := flag.String("out", "oui.txt.gz", "compressed table to write")
	flag.Parse()
	if err := generate(*input, *output); err != nil {
		log.Fatal(err)
	}
}

func generate(input, output string) error {
	source, err := os.Open(input)
	if err != nil {
		return err
	}
	defer source.Close()
	reader := csv.NewReader(source)
	reader.FieldsPerRecord = -1
	lines := make([]string, 0, 40_000)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if len(record) < 3 || record[0] != "MA-L" || len(record[1]) != 6 {
			continue
		}
		name := shortName(record[2])
		if name == "" || strings.EqualFold(name, "private") {
			continue
		}
		lines = append(lines, strings.ToLower(record[1])+"\t"+name)
	}
	slices.Sort(lines)
	lines = slices.Compact(lines)

	target, err := os.Create(output)
	if err != nil {
		return err
	}
	compressed, err := gzip.NewWriterLevel(target, gzip.BestCompression)
	if err != nil {
		return err
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(compressed, line); err != nil {
			return err
		}
	}
	if err := compressed.Close(); err != nil {
		return err
	}
	return target.Close()
}

// shortName trims legal forms and stray punctuation from an organization name.
func shortName(name string) string {
	name = strings.Join(strings.Fields(name), " ")
	for {
		trimmed := strings.TrimRight(legalSuffix.ReplaceAllString(name, ""), " ,.")
		if trimmed == name || trimmed == "" {
			break
		}
		name = trimmed
	}
	return strings.ReplaceAll(name, "\t", " ")
}
