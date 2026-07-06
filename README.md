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
