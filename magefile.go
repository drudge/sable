//go:build mage

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/pelletier/go-toml/v2"
)

const (
	airVersion                = "v1.65.1"
	developmentVersion        = "0.9.6-rc.3"
	goExperiment              = "jsonv2"
	releasePackage            = "github.com/drudge/sable/internal/version"
	containerImage            = "ghcr.io/drudge/sable"
	releaseBuilder            = "sable-release"
	templCommand              = "github.com/a-h/templ/cmd/templ"
	clusterReplicaDirectory   = "_work/cluster-dev/replica"
	releaseBranch             = "main"
	recordedVersionPattern    = `[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?`
	controlledRestartExitCode = 75
	goReleaserConfig          = `version: 2

project_name: sable

builds:
  - id: sable
    main: ./cmd/sable
    binary: sable
    env:
      - CGO_ENABLED=0
      - GOEXPERIMENT=jsonv2
    flags:
      - -trimpath
    ldflags:
      - -s -w
      - -X github.com/drudge/sable/internal/version.Release={{ .Version }}
      - -X github.com/drudge/sable/internal/version.Commit={{ .Commit }}
      - -X github.com/drudge/sable/internal/version.BuiltAt={{ .CommitDate }}
    mod_timestamp: "{{ .CommitTimestamp }}"
    goos:
      - darwin
      - freebsd
      - linux
      - windows
    goarch:
      - amd64
      - arm64

archives:
  - ids:
      - sable
    formats:
      - tar.gz
    format_overrides:
      - goos: windows
        formats:
          - zip
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    wrap_in_directory: true
    files:
      - LICENSE
      - README.md
      - config.example.toml
      - scripts/install.sh

checksum:
  name_template: checksums.txt
  algorithm: sha256

changelog:
  sort: asc
  filters:
    exclude:
      - '^docs:'
      - '^test:'
      - '^chore:'

release:
  prerelease: auto

snapshot:
  version_template: "{{ .Env.SABLE_SNAPSHOT_VERSION }}"
`
	goReleaserDockerConfig = `

dockers_v2:
  - id: sable
    ids:
      - sable
    dockerfile: Dockerfile
    images:
      - "ghcr.io/drudge/sable"
    tags:
      - "{{ .Version }}"
      - "{{ if not .Prerelease }}latest{{ end }}"
      - "{{ if .Prerelease }}next{{ end }}"
    platforms:
      - linux/amd64
      - linux/arm64
    extra_files:
      - docker
    build_args:
      VERSION: "{{ .Version }}"
      REVISION: "{{ .FullCommit }}"
      CREATED: "{{ .Date }}"
    labels:
      "org.opencontainers.image.title": "Sable"
      "org.opencontainers.image.description": "Modern, high-performance DNS server"
      "org.opencontainers.image.source": "https://github.com/drudge/sable"
      "org.opencontainers.image.licenses": "MIT"
      "org.opencontainers.image.version": "{{ .Version }}"
      "org.opencontainers.image.revision": "{{ .FullCommit }}"
      "org.opencontainers.image.created": "{{ .Date }}"
`
)

// Default builds the Sable executable.
var Default = Build

// Generate regenerates templ components.
func Generate(ctx context.Context) error {
	return run(ctx, nil, "go", "run", "-mod=mod", templCommand, "generate", "-path", "internal/web/pages")
}

// CheckGenerated verifies that generated templ components are current.
func CheckGenerated(ctx context.Context) error {
	return run(ctx, nil, "go", "run", "-mod=mod", templCommand, "generate", "-path", "internal/web/pages", "-check")
}

// Format formats application and Mage source files.
func Format(ctx context.Context) error {
	if err := run(ctx, nil, "go", "fmt", "./cmd/...", "./internal/..."); err != nil {
		return err
	}
	return run(ctx, nil, "gofmt", "-w", "magefile.go")
}

// Test runs the complete Go test suite.
func Test(ctx context.Context) error {
	return run(ctx, nil, "go", "test", "./...")
}

// ClusterTest runs two complete Sable nodes and verifies replica enrollment,
// status telemetry, state synchronization, and a planned primary handoff.
func ClusterTest(ctx context.Context) error {
	return run(ctx, nil, "go", "test", "-tags=integration", "-run", "^TestTwoNodeClusterReplicaEnrollmentAndSynchronization$", "-v", "./internal/app")
}

// ReleaseSmoke builds the production-style single binary and exercises it as a
// standalone DNS server and as both members of a two-node cluster.
func ReleaseSmoke(ctx context.Context) error {
	if err := Build(ctx); err != nil {
		return err
	}
	binaryPath, err := filepath.Abs(filepath.Join("bin", "sable"))
	if err != nil {
		return fmt.Errorf("resolve Sable binary: %w", err)
	}
	binarySize, binaryDigest, err := releaseSmokeBinaryIdentity(binaryPath)
	if err != nil {
		return err
	}
	fmt.Printf("Release smoke binary: %s (%d bytes, sha256=%s)\n", binaryPath, binarySize, binaryDigest)
	return run(ctx, []string{"SABLE_INTEGRATION_BINARY=" + binaryPath},
		"go", "test", "-count=1", "-tags=integration",
		"-run", "^(TestReleaseBinarySmoke|TestTwoNodeClusterReplicaEnrollmentAndSynchronization)$",
		"-v", "./internal/app")
}

func releaseSmokeBinaryIdentity(path string) (int64, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", fmt.Errorf("open release-smoke binary: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, "", fmt.Errorf("inspect release-smoke binary: %w", err)
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return 0, "", fmt.Errorf("hash release-smoke binary: %w", err)
	}
	return info.Size(), fmt.Sprintf("%x", digest.Sum(nil)), nil
}

// Demo brings up the Vandelay Industries demonstration deployment and leaves it
// running. Nothing in it is real: a mock UniFi controller serves the fixture,
// the block lists are generated offline, and the traffic history is seeded into
// a throwaway database under _work/demo.
func Demo(ctx context.Context) error {
	if err := Build(ctx); err != nil {
		return err
	}
	return run(ctx, nil, "go", "run", "./scripts/demo", "-keep")
}

// Screenshots rebuilds the Vandelay Industries demonstration deployment and
// photographs its console into docs/assets/screenshots.
func Screenshots(ctx context.Context) error {
	if err := Build(ctx); err != nil {
		return err
	}
	return run(ctx, nil, "go", "run", "./scripts/demo", "-out", filepath.Join("docs", "assets", "screenshots"))
}

// ClusterReplica runs a persistent second Sable node for interactive cluster UI testing.
func ClusterReplica(ctx context.Context) error {
	if err := Build(ctx); err != nil {
		return err
	}
	configurationPath, err := ensureClusterReplicaConfiguration()
	if err != nil {
		return err
	}
	binaryPath, err := filepath.Abs(filepath.Join("bin", "sable"))
	if err != nil {
		return fmt.Errorf("resolve Sable binary: %w", err)
	}
	fmt.Println("Primary console: http://127.0.0.1:5380 (start separately with: mage dev)")
	fmt.Println("Replica console: http://127.0.0.1:5382")
	fmt.Println("Replica DNS:     127.0.0.1:8054")
	fmt.Println("Replica state:   " + clusterReplicaDirectory)
	return runSupervisedSable(ctx, binaryPath, filepath.Base(configurationPath), filepath.Dir(configurationPath))
}

// Race runs the complete test suite with the race detector.
func Race(ctx context.Context) error {
	return run(ctx, nil, "go", "test", "-race", "./...")
}

// Vet runs Go's static analyzer.
func Vet(ctx context.Context) error {
	return run(ctx, nil, "go", "vet", "./...")
}

// Verify checks generated source, tests, and static analysis.
func Verify(ctx context.Context) error {
	if err := CheckGenerated(ctx); err != nil {
		return err
	}
	if err := Test(ctx); err != nil {
		return err
	}
	return Vet(ctx)
}

// Build generates components and builds the static single binary in bin/sable.
func Build(ctx context.Context) error {
	if err := Generate(ctx); err != nil {
		return err
	}
	if err := os.MkdirAll("bin", 0o755); err != nil {
		return fmt.Errorf("create bin directory: %w", err)
	}
	ldflags := strings.Join([]string{
		"-s", "-w",
		"-X", releasePackage + ".Release=" + environmentOr("VERSION", developmentVersion),
		"-X", releasePackage + ".Commit=" + buildCommit(),
		"-X", releasePackage + ".BuiltAt=" + environmentOr("BUILT_AT", time.Now().UTC().Format(time.RFC3339)),
	}, " ")
	return run(ctx, []string{"CGO_ENABLED=0"}, "go", "build", "-trimpath", "-ldflags", ldflags, "-o", "bin/sable", "./cmd/sable")
}

// Bench runs Sable's DNS, zone-storage, dynamic-update, and blocking microbenchmarks.
func Bench(ctx context.Context) error {
	return run(ctx, nil, "go", "test", "-run", "^$", "-bench=.", "-benchmem", "./internal/dnsserver", "./internal/store", "./internal/app", "./internal/blocking")
}

// BenchmarkCompare runs a clean, isolated dnsperf comparison against Technitium.
func BenchmarkCompare(ctx context.Context) error {
	if err := Generate(ctx); err != nil {
		return err
	}
	return run(ctx, nil, "./benchmarks/compare.sh")
}

// Dev starts the pinned Air live-development workflow.
func Dev(ctx context.Context) error {
	return run(ctx, nil, "go", "run", "github.com/air-verse/air@"+airVersion, "-c", ".air.toml")
}

// ReleaseCheck validates Sable's generated GoReleaser configuration.
func ReleaseCheck(ctx context.Context) error {
	return withGoReleaserConfigEnvironment(ctx, []string{"SABLE_CONTAINER_RELEASE=true"}, "check")
}

// Snapshot verifies the repository and creates unpublished release artifacts.
func Snapshot(ctx context.Context) error {
	if err := Verify(ctx); err != nil {
		return err
	}
	if err := ReleaseSmoke(ctx); err != nil {
		return err
	}
	return withGoReleaserConfig(ctx, "release", "--snapshot", "--clean")
}

// DockerSnapshot creates local amd64 and arm64 container images without
// publishing them. Archive snapshots remain available without a Docker daemon.
func DockerSnapshot(ctx context.Context) error {
	if err := requireDocker(ctx); err != nil {
		return err
	}
	if err := CheckGenerated(ctx); err != nil {
		return err
	}
	return withGoReleaserConfigEnvironment(ctx, []string{"SABLE_CONTAINER_RELEASE=true"},
		"release", "--snapshot", "--clean")
}

// DockerSmoke builds the snapshot images and starts the native-architecture
// image, then verifies its version command and public health endpoint.
func DockerSmoke(ctx context.Context) error {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return fmt.Errorf("container smoke does not support host architecture %q", runtime.GOARCH)
	}
	if err := DockerSnapshot(ctx); err != nil {
		return err
	}
	version, err := releaseSnapshotVersion()
	if err != nil {
		return err
	}
	image := fmt.Sprintf("%s:%s-%s", containerImage, version, runtime.GOARCH)
	if err := run(ctx, nil, "docker", "run", "--rm", "--entrypoint", "/usr/local/bin/sable", image, "version"); err != nil {
		return fmt.Errorf("run container version smoke: %w", err)
	}
	name := fmt.Sprintf("sable-smoke-%d", time.Now().UnixNano())
	defer removeContainer(context.Background(), name)
	if err := run(ctx, nil, "docker", "run", "--detach", "--name", name,
		"--publish", "127.0.0.1::5380/tcp", image); err != nil {
		return fmt.Errorf("start container smoke: %w", err)
	}
	portOutput, err := output(ctx, "docker", "port", name, "5380/tcp")
	if err != nil {
		return fmt.Errorf("inspect container HTTP port: %w", err)
	}
	port, err := publishedPort(portOutput)
	if err != nil {
		return err
	}
	if err := waitForContainerHealth(ctx, "http://127.0.0.1:"+port+"/api/v1/health"); err != nil {
		logs, _ := output(context.Background(), "docker", "logs", name)
		return fmt.Errorf("%w\ncontainer logs:\n%s", err, logs)
	}
	fmt.Printf("Container smoke passed: %s (HTTP 127.0.0.1:%s)\n", image, port)
	return nil
}

// Release bumps every recorded version, verifies the repository, then commits,
// tags, pushes, and publishes the release through GoReleaser. The version may be
// given with or without its leading "v", as in "mage release 0.8.0-rc.2".
func Release(ctx context.Context, version string) error {
	release, err := parseReleaseVersion(version)
	if err != nil {
		return err
	}
	tag := "v" + release
	branch := environmentOr("RELEASE_BRANCH", releaseBranch)
	if err := requireReleaseBranch(ctx, branch); err != nil {
		return err
	}
	if err := requireCleanWorktree(ctx); err != nil {
		return err
	}
	if err := requireDocker(ctx); err != nil {
		return err
	}
	if err := run(ctx, nil, "git", "pull", "--ff-only", "origin", branch); err != nil {
		return err
	}
	if err := requireUnusedTag(ctx, tag); err != nil {
		return err
	}
	updated, err := bumpVersionReferences(release)
	if err != nil {
		return err
	}
	fmt.Printf("Recorded %s in %d file(s)\n", release, updated)
	if err := os.Setenv("VERSION", release); err != nil {
		return fmt.Errorf("set the release version for the smoke build: %w", err)
	}
	if err := Verify(ctx); err != nil {
		return err
	}
	if err := ReleaseSmoke(ctx); err != nil {
		return err
	}
	message := "Sable " + tag
	if updated > 0 {
		if err := run(ctx, nil, "git", "commit", "--all", "--message", message); err != nil {
			return err
		}
	}
	if err := run(ctx, nil, "git", "tag", "--annotate", tag, "--message", message); err != nil {
		return err
	}
	if err := run(ctx, nil, "git", "push", "origin", branch); err != nil {
		return err
	}
	if err := run(ctx, nil, "git", "push", "origin", tag); err != nil {
		return err
	}
	return publishCurrentTag(ctx)
}

// Publish verifies the repository and publishes the current tag through
// GoReleaser. Release calls the same publication step after tagging, so this
// target exists to retry a publication whose tag is already pushed.
func Publish(ctx context.Context) error {
	if err := Verify(ctx); err != nil {
		return err
	}
	if err := ReleaseSmoke(ctx); err != nil {
		return err
	}
	if err := requireDocker(ctx); err != nil {
		return err
	}
	return publishCurrentTag(ctx)
}

func publishCurrentTag(ctx context.Context) error {
	return withGoReleaserConfigEnvironment(ctx, []string{"SABLE_CONTAINER_RELEASE=true"}, "release", "--clean")
}

// versionReference locates one recorded version so a release can rewrite every
// copy of it. Each expression keeps the text around the version in capture
// groups and must match at least once, so a moved reference fails the release
// instead of silently going stale.
type versionReference struct {
	path       string
	expression *regexp.Regexp
}

func versionReferences() []versionReference {
	reference := func(path, pattern string) versionReference {
		return versionReference{path: path, expression: regexp.MustCompile(pattern)}
	}
	return []versionReference{
		reference("magefile.go", `(developmentVersion\s+= ")`+recordedVersionPattern+`(")`),
		reference("internal/version/version.go", `(Release\s+= ")`+recordedVersionPattern+`(")`),
		reference("README.md", `(SABLE_VERSION=)`+recordedVersionPattern),
		reference("README.md", `(--version v)`+recordedVersionPattern),
		reference("README.md", `(ghcr\.io/drudge/sable:)`+recordedVersionPattern),
		reference("docs/proxmox.md", `(SABLE_VERSION=)`+recordedVersionPattern),
	}
}

func bumpVersionReferences(release string) (int, error) {
	contents := map[string][]byte{}
	for _, reference := range versionReferences() {
		current, cached := contents[reference.path]
		if !cached {
			read, err := os.ReadFile(reference.path)
			if err != nil {
				return 0, fmt.Errorf("read %s: %w", reference.path, err)
			}
			current = read
		}
		if reference.expression.Find(current) == nil {
			return 0, fmt.Errorf("%s no longer contains a version matching %s", reference.path, reference.expression)
		}
		contents[reference.path] = reference.expression.ReplaceAll(current, []byte("${1}"+release+"${2}"))
	}
	updated := 0
	for path, rewritten := range contents {
		current, err := os.ReadFile(path)
		if err != nil {
			return 0, fmt.Errorf("read %s: %w", path, err)
		}
		if string(current) == string(rewritten) {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return 0, fmt.Errorf("inspect %s: %w", path, err)
		}
		if err := os.WriteFile(path, rewritten, info.Mode().Perm()); err != nil {
			return 0, fmt.Errorf("write %s: %w", path, err)
		}
		updated++
	}
	return updated, nil
}

func parseReleaseVersion(version string) (string, error) {
	release := strings.TrimPrefix(strings.TrimSpace(version), "v")
	if !regexp.MustCompile(`^` + recordedVersionPattern + `$`).MatchString(release) {
		return "", fmt.Errorf("release version %q is not a semantic version such as 0.8.0 or 0.8.0-rc.2", version)
	}
	return release, nil
}

func requireReleaseBranch(ctx context.Context, branch string) error {
	current, err := output(ctx, "git", "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return fmt.Errorf("read current branch: %w", err)
	}
	if current != branch {
		return fmt.Errorf("releases are cut from %s, but %s is checked out; set RELEASE_BRANCH to override", branch, current)
	}
	return nil
}

func requireCleanWorktree(ctx context.Context) error {
	status, err := output(ctx, "git", "status", "--porcelain")
	if err != nil {
		return fmt.Errorf("read repository status: %w", err)
	}
	if status != "" {
		return fmt.Errorf("the repository has uncommitted changes:\n%s", status)
	}
	return nil
}

func requireUnusedTag(ctx context.Context, tag string) error {
	local, err := output(ctx, "git", "tag", "--list", tag)
	if err != nil {
		return fmt.Errorf("list local tags: %w", err)
	}
	if local != "" {
		return fmt.Errorf("tag %s already exists locally", tag)
	}
	remote, err := output(ctx, "git", "ls-remote", "--tags", "origin", "refs/tags/"+tag)
	if err != nil {
		return fmt.Errorf("list published tags: %w", err)
	}
	if remote != "" {
		return fmt.Errorf("tag %s is already published", tag)
	}
	return nil
}

func withGoReleaserConfig(ctx context.Context, arguments ...string) error {
	return withGoReleaserConfigEnvironment(ctx, nil, arguments...)
}

func withGoReleaserConfigEnvironment(ctx context.Context, environment []string, arguments ...string) error {
	file, err := os.CreateTemp("", "sable-goreleaser-*.yaml")
	if err != nil {
		return fmt.Errorf("create temporary GoReleaser configuration: %w", err)
	}
	path := file.Name()
	defer os.Remove(path)
	configuration := goReleaserConfig
	if containerReleaseEnabled(environment) {
		configuration += goReleaserDockerConfig
	}
	if _, err := file.WriteString(configuration); err != nil {
		file.Close()
		return fmt.Errorf("write temporary GoReleaser configuration: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary GoReleaser configuration: %w", err)
	}
	environment = append(environment, "SABLE_SNAPSHOT_VERSION="+environmentOr("VERSION", developmentVersion)+"-snapshot")
	if containerReleaseEnabled(environment) {
		environment = append(environment, "BUILDX_BUILDER="+releaseBuilderName())
	}
	arguments = append(arguments, "--config", path)
	return run(ctx, environment, environmentOr("GORELEASER", "goreleaser"), arguments...)
}

func releaseSnapshotVersion() (string, error) {
	contents, err := os.ReadFile(filepath.Join("dist", "metadata.json"))
	if err != nil {
		return "", fmt.Errorf("read GoReleaser metadata: %w", err)
	}
	var metadata struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(contents, &metadata); err != nil {
		return "", fmt.Errorf("decode GoReleaser metadata: %w", err)
	}
	if strings.TrimSpace(metadata.Version) == "" {
		return "", errors.New("GoReleaser metadata does not contain a snapshot version")
	}
	return metadata.Version, nil
}

func containerReleaseEnabled(environment []string) bool {
	for _, value := range environment {
		if value == "SABLE_CONTAINER_RELEASE=true" {
			return true
		}
	}
	return false
}

func requireDocker(ctx context.Context) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return errors.New("Docker is required for container snapshots and releases")
	}
	if _, err := output(ctx, "docker", "info", "--format", "{{.ServerVersion}}"); err != nil {
		return fmt.Errorf("Docker is installed but its daemon is not available: %w", err)
	}
	if _, err := output(ctx, "docker", "buildx", "version"); err != nil {
		return fmt.Errorf("Docker Buildx is required for multi-architecture images: %w", err)
	}
	return ensureReleaseBuilder(ctx)
}

// ensureReleaseBuilder prepares the Docker Buildx builder that publishes Sable's
// container images. Buildx's default "docker" driver cannot export manifest
// lists or SBOM attestations, so a multi-architecture publication fails unless
// BuildKit runs in a container.
func ensureReleaseBuilder(ctx context.Context) error {
	name := releaseBuilderName()
	driver, err := builderDriver(ctx, name)
	if err != nil {
		if _, err := output(ctx, "docker", "buildx", "create", "--name", name,
			"--driver", "docker-container", "--bootstrap"); err != nil {
			return fmt.Errorf("create Docker Buildx builder %q: %w", name, err)
		}
		return nil
	}
	if driver != "docker-container" {
		return fmt.Errorf("Docker Buildx builder %q uses the %q driver; multi-architecture images require the docker-container driver", name, driver)
	}
	return nil
}

func releaseBuilderName() string {
	return environmentOr("BUILDX_BUILDER", releaseBuilder)
}

func builderDriver(ctx context.Context, name string) (string, error) {
	details, err := output(ctx, "docker", "buildx", "inspect", name)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(details, "\n") {
		if value, found := strings.CutPrefix(strings.TrimSpace(line), "Driver:"); found {
			return strings.TrimSpace(value), nil
		}
	}
	return "", fmt.Errorf("Docker Buildx did not report a driver for builder %q", name)
}

func output(ctx context.Context, name string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	result, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(result)))
	}
	return strings.TrimSpace(string(result)), nil
}

func publishedPort(value string) (string, error) {
	line := strings.TrimSpace(strings.Split(value, "\n")[0])
	separator := strings.LastIndexByte(line, ':')
	if separator < 0 || separator == len(line)-1 {
		return "", fmt.Errorf("parse published container port from %q", value)
	}
	return line[separator+1:], nil
}

func waitForContainerHealth(ctx context.Context, address string) error {
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	client := &http.Client{Timeout: time.Second}
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			return fmt.Errorf("create container health request: %w", err)
		}
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("timed out waiting for container health at %s", address)
		case <-ticker.C:
		}
	}
}

func removeContainer(ctx context.Context, name string) {
	command := exec.CommandContext(ctx, "docker", "rm", "--force", "--volumes", name)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	_ = command.Run()
}

func run(ctx context.Context, environment []string, name string, arguments ...string) error {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = append(os.Environ(), "GOEXPERIMENT="+goExperiment)
	command.Env = append(command.Env, environment...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func ensureClusterReplicaConfiguration() (string, error) {
	configurationPath := filepath.Join(clusterReplicaDirectory, "sable.toml")
	if _, err := os.Stat(configurationPath); err == nil {
		return configurationPath, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("inspect replica configuration: %w", err)
	}
	if err := os.MkdirAll(clusterReplicaDirectory, 0o700); err != nil {
		return "", fmt.Errorf("create replica workspace: %w", err)
	}
	replica := config.Defaults()
	replica.Server.HTTPListen = "127.0.0.1:5382"
	replica.Server.DNSListen = []string{"127.0.0.1:8054"}
	replica.Database.DSN = "data/sable.db"
	replica.Resolver.DNSSECTrustAnchorUpdates = false
	replica.Cluster.NodeName = "ns2"
	replica.Cluster.AdvertiseURL = "https://localhost:5444"
	replica.Reload.Watch = true
	contents, err := toml.Marshal(replica)
	if err != nil {
		return "", fmt.Errorf("encode replica configuration: %w", err)
	}
	if err := os.WriteFile(configurationPath, contents, 0o600); err != nil {
		return "", fmt.Errorf("write replica configuration: %w", err)
	}
	return configurationPath, nil
}

func runSupervisedSable(ctx context.Context, binaryPath, configurationName, workingDirectory string) error {
	for {
		command := exec.CommandContext(ctx, binaryPath, "serve", "--config", configurationName)
		command.Dir = workingDirectory
		command.Stdin = os.Stdin
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		err := command.Run()
		if ctx.Err() != nil {
			return nil
		}
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == controlledRestartExitCode {
			fmt.Println("Replica requested a controlled restart; starting it again...")
			continue
		}
		if err != nil {
			return fmt.Errorf("replica stopped: %w", err)
		}
		return nil
	}
}

func environmentOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func buildCommit() string {
	if value := strings.TrimSpace(os.Getenv("COMMIT")); value != "" {
		return value
	}
	output, err := exec.Command("git", "rev-parse", "--short=12", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}
