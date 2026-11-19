# Contributing

Thanks for helping make DOOH screens safer.

## Ground rules
- Templates must be **detection only** unless they are tagged `intrusive` (anything that sends
  credentials or changes device state). Intrusive templates only run with `--intrusive`.
- Every template needs: a unique `id`, `author`, `severity`, a `description`, an
  `info.remediation` (what the owner should do), and an OWASP IoT mapping in `metadata.owasp-iot`.
- Matchers must be specific. A template that matches a plain web server is a bug. Use
  `matchers-condition: and` with a status check plus a vendor string.
- Test new templates against a real device, and against a plain web server to prove they do not match it.
- Keep the scanner output neutral: no product marketing in what the tool prints.

## Build and test
```
mvn verify                                   # compile + unit tests (incl. planted-binary tests) + template lint
scripts/platform-test.sh                     # on your OS/CPU: install Nuclei, validate every template, false-positive check
nuclei -validate -t templates                # every template must load (the tested Nuclei version is in NucleiInstaller.VERSION)
scripts/build-bundle.sh <platform> <version> # optional: build the self-contained bundle for your own OS/CPU (needs JDK 17)
```

## Pull requests
Describe what the change detects, how you tested it (device model/firmware), and include the
output of `nuclei -validate`. CI runs the tests and builds the bundle on Linux x64/arm64, macOS Intel/Apple Silicon and Windows. By contributing you agree your work is released under the Apache License 2.0 (see LICENSE).
Please follow the [Code of Conduct](CODE_OF_CONDUCT.md). Once templates are verified on real devices we intend to
contribute them back to ProjectDiscovery's public template library.
