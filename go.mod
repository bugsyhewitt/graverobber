module github.com/bugsyhewitt/graverobber

go 1.24.0

// Third-party dependencies are intentionally omitted here. Run `go mod tidy`
// (in a network-enabled environment) to populate require directives from the
// import statements. Expected dependencies for v1.0:
//
//   github.com/spf13/cobra                       CLI framework  (cmd/)
//   github.com/miekg/dns                         DNS resolution (pkg/resolver, build step)
//   github.com/projectdiscovery/retryablehttp-go HTTP w/ retry  (pkg/detectors, build step)
//   github.com/projectdiscovery/ratelimit        per-host rate  (pkg/scanner, build step)
//
// NOTE: replace the module path's `bugsy` segment with your GitHub handle/org,
// then update internal imports in one pass:
//   grep -rl 'github.com/bugsyhewitt/graverobber' --include='*.go' . \
//     | xargs sed -i 's#github.com/bugsyhewitt/graverobber#github.com/YOURHANDLE/graverobber#g'

require (
	github.com/miekg/dns v1.1.72
	github.com/spf13/cobra v1.10.2
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
)
