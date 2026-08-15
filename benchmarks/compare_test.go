package benchmarks

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCompareKeepsWarmupAndMeasuredEvidenceSeparate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("benchmark harness requires a POSIX shell")
	}

	temporaryDirectory := t.TempDir()
	binDirectory := filepath.Join(temporaryDirectory, "bin")
	if err := os.Mkdir(binDirectory, 0o755); err != nil {
		t.Fatalf("create fake tool directory: %v", err)
	}

	dnsperfPath := filepath.Join(binDirectory, "dnsperf")
	dnsperf := `#!/bin/sh
if [ "${1:-}" = "-H" ]; then
	printf '%s\n' 'fake dnsperf help'
	exit 0
fi
seconds=1
while [ "$#" -gt 0 ]; do
	if [ "$1" = "-l" ]; then
		shift
		seconds=$1
	fi
	shift
done
sent=$((seconds * 100))
printf '%s\n' \
	"Queries sent:         $sent" \
	"Queries completed:    $sent" \
	'Queries lost:         0' \
	"Response codes:       NOERROR $sent (100.00%)" \
	"Run time (s):         $seconds.000000" \
	'Queries per second:   100.000000' \
	'Average Latency (s):  0.001000' \
	'Latency StdDev (s):   0.000100'
`
	if err := os.WriteFile(dnsperfPath, []byte(dnsperf), 0o755); err != nil {
		t.Fatalf("write fake dnsperf: %v", err)
	}

	queryPath := filepath.Join(temporaryDirectory, "queries.txt")
	if err := os.WriteFile(queryPath, []byte("example.com A\n"), 0o600); err != nil {
		t.Fatalf("write query corpus: %v", err)
	}
	resultsDirectory := filepath.Join(temporaryDirectory, "results")

	command := exec.Command("./compare.sh")
	command.Env = append(os.Environ(),
		"PATH="+binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"),
		"MODE=external",
		"RUNS=1",
		"WARMUP=1",
		"DURATION=2",
		"OUTSTANDING=1",
		"QUERY_FILE="+queryPath,
		"RESULTS_DIRECTORY="+resultsDirectory,
		"SABLE_PORT=19053",
		"SABLE_HTTP_PORT=19080",
		"TECHNITIUM_PORT=19054",
		"TECHNITIUM_HTTP_PORT=19081",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run comparison harness: %v\n%s", err, output)
	}

	for _, product := range []string{"sable", "technitium"} {
		warmup := readBenchmarkEvidence(t, filepath.Join(resultsDirectory, "trial-01", product+"-warmup.txt"))
		measured := readBenchmarkEvidence(t, filepath.Join(resultsDirectory, "trial-01", product+"-dnsperf.txt"))
		if !strings.Contains(warmup, "Queries sent:         100") {
			t.Fatalf("%s warmup evidence was overwritten:\n%s", product, warmup)
		}
		if !strings.Contains(measured, "Queries sent:         200") {
			t.Fatalf("%s measured evidence is incomplete:\n%s", product, measured)
		}
	}

	summary := readBenchmarkEvidence(t, filepath.Join(resultsDirectory, "summary.tsv"))
	if strings.Count(strings.TrimSpace(summary), "\n") != 2 {
		t.Fatalf("expected header and two measured summary rows:\n%s", summary)
	}
}

func readBenchmarkEvidence(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}
