# appliance-ctl

Source for the `zonctl` CLI.

This repo owns the Zon lifecycle CLI and bundle assembly/verification logic.
`appliance-release` consumes the built `zonctl` binary as an external input
when it assembles a product bundle.

## Common commands

```bash
make build
make unit-test
make verify
```

## Offline builds

Dependencies are vendored under `vendor/` and committed to the repo, so
`make build` (and everything `verify` runs) compiles with no network
access required — the same discipline `appliance-code` follows, for the
same reason: the release pipeline that assembles the offline appliance
bundle also builds `zonctl` as one of its steps, and that build should
not depend on a reachable module proxy either.

After changing any `require` in `go.mod`, run `make vendor` and commit
the result. This repo has no `go.work`, so `go build`/`test`/`vet`
default to `-mod=vendor` on their own the moment `vendor/` exists, and
fail immediately with an "inconsistent vendoring" error if `go.mod` and
`vendor/modules.txt` ever disagree — there's no separate drift check to
remember to run.
