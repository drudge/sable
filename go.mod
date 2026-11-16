module github.com/drudge/sable

go 1.27

toolchain go1.27.4

require (
	github.com/a-h/templ v0.3.1118
	github.com/fsnotify/fsnotify v1.10.1
	github.com/fxamacker/cbor/v2 v2.10.0
	github.com/go-webauthn/webauthn v0.18.2
	github.com/insomniacslk/dhcp v0.0.0-20261014062924-c6bb46ad3f3a
	github.com/jackc/pgx/v5 v5.13.0
	github.com/miekg/dns v1.1.73
	github.com/pelletier/go-toml/v2 v2.4.3
	github.com/quic-go/quic-go v0.65.0
	github.com/yuin/goldmark v1.8.7
	golang.org/x/crypto v0.59.0
	golang.org/x/mod v0.43.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.50.0
	golang.org/x/term v0.48.0
	modernc.org/sqlite v1.62.0
)

require (
	github.com/a-h/parse v0.0.42 // indirect
	github.com/andybalholm/brotli v1.3.0 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cli/browser v1.3.0 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/magefile/mage v1.17.2 // indirect
	github.com/mattn/go-colorable v0.1.16 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/natefinch/atomic v1.0.1 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/philhofer/fwd v1.2.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/tinylib/msgp v1.6.5 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/telemetry v0.0.0-20261021172232-6cd571d43fbb // indirect
	golang.org/x/text v0.44.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.org/x/vuln v1.9.0 // indirect
	modernc.org/libc v1.80.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

tool (
	github.com/a-h/templ/cmd/templ
	github.com/magefile/mage
	golang.org/x/vuln/cmd/govulncheck
)
