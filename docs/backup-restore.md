# Backup and restore

Keep the signed appliance bundle separate from backups. A bundle supplies the
software; backups contain only appliance configuration and declared persistent
data.

## Configuration only

Export configuration as a portable encrypted archive. Keep the 32-byte key
file separately from the archive.

```bash
sudo zonctl configuration-export \
  --configuration-endpoint https://appliance.example \
  --configuration-token-file /secure/operator-token \
  --configuration-archive-key-file /secure/config.key \
  --configuration-archive /secure/appliance.zonconfig
```

After an appliance is running, import it with explicit replacement:

```bash
sudo zonctl configuration-import \
  --configuration-endpoint https://appliance.example \
  --configuration-token-file /secure/operator-token \
  --configuration-archive-key-file /secure/config.key \
  --configuration-archive /secure/appliance.zonconfig \
  --replace-configuration
```

The Admin **Backup & Restore** page provides the same configuration workflow.

## System backup

A system backup contains the PostgreSQL logical dump, encrypted configuration
archive, blob-storage objects, and installation receipt. It does not contain
the signed appliance bundle, workspace sources, build caches, models, logs, or
registry cache. Blob storage is briefly quiesced to make its archive
consistent.

```bash
sudo zonctl backup \
  --recovery-set /secure/recovery-set \
  --configuration-endpoint https://appliance.example \
  --configuration-token-file /secure/operator-token \
  --configuration-archive-key-file /secure/config.key
```

The destination directory must be empty. Store the recovery-set directory and
the separate key file off the appliance.

## Restore after installation

First install a compatible signed appliance bundle normally. Then restore the
recovery set on the control-plane host:

```bash
sudo zonctl restore \
  --recovery-set /secure/recovery-set \
  --confirm restore-recovery-set \
  --acknowledge-data-loss
```

This replaces PostgreSQL and blob-storage data and restarts affected services.
It intentionally requires explicit data-loss acknowledgement. Import the
configuration archive afterwards using the configuration-only command above.

## Restore during installation

For a clean target, the installer can restore the same recovery set while it
deploys the appliance:

```bash
sudo zonctl install --bundle-dir /path/to/foundation \
  --bootstrap-mode restore-recovery-set \
  --recovery-set /secure/recovery-set \
  --configuration-archive-key-file /secure/config.key \
  --confirm restore-recovery-set
```

Use this mode only for a clean appliance target. The recovery-set platform
version and PostgreSQL image must match the signed bundle. After the appliance
is healthy, import the configuration archive from that recovery set with the
configuration-only command above.
