# Appliance CLI Invariants

These rules apply to all implementation and documentation in this repository.

## Local Verification Discipline

- Any time you edit this repository, run `make verify` in this repository before considering the work complete.
- Apply this even for small code, schema, test, Makefile, or documentation changes unless the user explicitly tells you not to run verification.
- If `make verify` fails, fixing that failure becomes the first follow-up task before any further feature work or close-out.
- Do not treat the task as done while `make verify` is failing. Either fix the failure or report the exact blocker and the failing log/location.
