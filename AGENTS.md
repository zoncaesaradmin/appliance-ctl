# Appliance CLI Invariants

These rules apply to all implementation and documentation in this repository.

## Workload Identity And Storage Security

- Run K3s rootful for the initial appliance baseline, but require appliance application containers to run as non-root.
- Assign fixed numeric UID/GID values for every component and keep them stable across releases; never rely only on Linux usernames in installer logic, diagnostics, evidence, or docs.
- Use pod-level `runAsUser`, `runAsGroup`, `runAsNonRoot`, `fsGroup`, and `fsGroupChangePolicy: OnRootMismatch` for application and workflow pods rendered or validated by this CLI.
- Use distinct per-component UIDs/GIDs and a separate shared filesystem GID for writable storage shared across components or workflow pods. The shared GID must not be the same number as a service UID.
- Use setgid directories and group-writable modes such as `2770` for shared writable storage; never use `chmod 777` as the normal solution.
- Give each service its own PVC unless the storage is genuinely shared. Treat every writable host mount or `hostPath` as a security-sensitive product interface that must be documented, ownership-checked, and preserved or wiped only by explicit lifecycle policy.
- Keep application container root filesystems read-only and mount only explicit writable paths.
- Use root init containers only as documented, narrow ownership-preparation or migration mechanisms.
- Validate normal workloads against Pod Security Admission, preferably the Restricted profile. Any required exception, such as a documented host-visible workspace or host log path, must be explicit.
- Installer, verification, support bundles, and health diagnostics must include storage ownership and writeability checks for appliance-owned writable paths, including service log directories and builder workspace storage.
- Test fresh install, upgrade, rollback, backup restore, and machine migration paths when changing UID/GID, storage, PVC, hostPath, or ownership behavior.

## Local Verification Discipline

- Any time you edit this repository, run `make verify` in this repository before considering the work complete.
- Apply this even for small code, schema, test, Makefile, or documentation changes unless the user explicitly tells you not to run verification.
- If `make verify` fails, fixing that failure becomes the first follow-up task before any further feature work or close-out.
- Do not treat the task as done while `make verify` is failing. Either fix the failure or report the exact blocker and the failing log/location.
