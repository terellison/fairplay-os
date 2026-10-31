# Part 2 of #27 (perf + socket): handoff notes

WIP, not pushed. Delete this file before opening the PR.

Based on master at #34; merge origin/master (and #36 once it lands) first.
Violation kinds: 35 `PerfCpu`, 36 `PerfTarget` (30-34 are #36's).

## What's here

- `crates/fairplay-ebpf/src/hooks/perf_event_open.rs`: two LSM programs.
  - `perf_event_open` denies type `PERF_SECURITY_CPU` while `PERF_GUARD[0] != 0`.
  - `perf_event_alloc` denies a per-task event (`event->hw.target`) on a protected
    process or on a self-protected fairplayd, using the `ptrace_access_check` rule.
  - Both skip kernel threads; the alloc hook also skips inherited events (`event->parent`).
- `PERF_GUARD` map (`maps.rs`, `MAP_PERF_GUARD`).
  - Synced by `Daemon::sync_perf_guard`: on while a session runs, a domain is draining,
    or `--protect`/`--allow` was given (`protected_from_cli`).
  - Turned on in `register` before the PROTECTED insert.
- fairplayd: routes `PerfCpu` to every running session (`record_machine_wide`), adds
  `hook_name` entries, and lists both programs in `LSM_PROGRAMS`.
- Socket check: `fairplay_api::client::check_server`.
  - Requires a root server (`SO_PEERCRED`), plus the `$FAIRPLAYD_PID` pid when that
    variable is set.
  - fairplayd sets `FAIRPLAYD_PID` in `launch::prepare`.
  - The PR must say that attestation is the real answer.
- `cheatsim perf [--pid N]`: a software clock event sampling user regs and stack.
- `vm/test-milestone6.sh`: perf and fake-socket checks, inside the "still works" step.
- Unit tests pass.

## Open bugs

1. **PERF_GUARD is never set.** Manual run: fairplayd with `--protect <sleep pid>`
   (so `protected_from_cli()` should have set it). Both programs were loaded, but
   `bpftool map dump name PERF_GUARD` showed `00 00 00 00`, and CPU-wide perf opened.
   - Check that `BpfMap::set_perf_guard` writes the map the programs use: compare the
     map id in the programs (`bpftool prog show`) with what fairplayd took.
   - Check that `protected_from_cli` runs at all.
   - In the m6 run, per-process perf on the game and on fairplayd *was* refused. So the
     alloc hook works; it is the guard path for CPU-wide events that's suspect.
2. **DENIED lines carry mode 0x6, not 0x1**, for a `PERF_TYPE_SOFTWARE` event.
   - Check which field and offset is read. The code reads `attr->type_` in
     `perf_event_open` and `event->attr.type_` in `perf_event_alloc`.
   - The lead notes that on arm64 `event->pmu->type` is often 6. Confirm the field the
     kernel hands the hook, and whether bindgen's `perf_event_attr` layout matches.
   - The m6 regexes expect `mode=0x1`. Fix the read, or the expectation, but not both
     blindly.

## Not yet verified

- That `event->hw.target` is set before `security_perf_event_alloc` on 6.8. The refusals
  in m6 suggest it is.
- m4/m5/m9/m9b have not been run on this branch.
