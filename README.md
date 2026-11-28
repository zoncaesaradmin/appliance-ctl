# appliance-ctl

These three repositories form the Zon appliance platform:

- `appliance-code` is the product source: backend services, shared UI, Geo UI, Helm charts, metadata catalogs, image definitions, and component tests.
- `appliance-ctl` contains `zonctl`, the installer and lifecycle controller. It validates signed release inputs, manages K3s and Helm, deploys services, handles secrets/storage, and performs health checks, upgrades, rollback, and diagnostics.
- `appliance-release` is the release orchestration and packaging layer. It builds and publishes pinned artifacts, assembles the signed offline bundle, and coordinates build/install verification.

The normal flow is: `appliance-code` produces product artifacts → `appliance-release` packages and signs them → `appliance-ctl` installs and operates them. Cross-repository changes must keep the signed manifest, image digests, chart values, namespaces, service endpoints, installer behavior, and tests aligned.

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

See [Backup and restore](docs/backup-restore.md) for the supported
configuration-only and system-backup workflows.

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
