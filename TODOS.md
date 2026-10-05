# TODOS

## Open

### Hook watchdog and bounded path expansion (HIGH)

**What:** a hook-wide watchdog that denies (exit 2) before Claude Code's hook timeout; no glob or realpath on remote paths; bounded, deadline-limited glob.

**Why:** round-2 security review (NEW-1). Slow path expansion can push the hook past the host timeout, and the host then runs the tool (fail open).

**Effort:** S-M
**Priority:** P1
**Depends on:** none.

### Decoy-path argument forms (HIGH)

**What:** normalize option prefixes on path words, fail closed when a path-scan cap is hit, and scan all string fields, not only known path keys.

**Why:** round-2 review (remaining 5). Some argument forms that name a decoy file aren't resolved to its path.

**Effort:** S
**Priority:** P1
**Depends on:** none.

### Self-protect residuals (MEDIUM)

**What:** cover Python startup files (`sitecustomize.py`, `.pth`) in site-packages, and stop `operator_paths` exempting an editable install's package from protection.

**Why:** round-2 review (remaining 6). Same-user tampering class, documented in README Limits.

**Effort:** S
**Priority:** P2
**Depends on:** none.

### Shared policy block

**What:** move the `fuse:` block into the suite's shared policy.yaml. Add `fuse` to gate's `_V2_BLOCKS`, agentbastion's `_TOOL_BLOCKS`, and a bastionsupply doctor floor.

**Why:** one policy file for the whole suite. It was deferred because no 0.1 consumer reads it, and today's gate/agentbastion loaders reject an unknown `fuse:` block.

**Context:** eng review D1 (`../bastionfuse-DESIGN.md`). The block schema is already v2-shaped, so it moves unchanged.

**Effort:** S (3 one-line bumps + contract tests in 3 repos)
**Priority:** P2
**Depends on:** gate integration.

### bastiongate integration

**What:** `gate: {fuse: true}`. The gate calls `Fuse.check` in `_handle_client_msg` for `tools/call` and `Fuse.record` on results. Honeytoken taint also becomes a flow-guard private source.

**Why:** MCP agents outside Claude Code get the same containment.

**Context:** release step 4. The outside voice flagged the overlap with the flow guard (OV8): reuse it, don't run a second taint engine.

**Effort:** M
**Priority:** P2
**Depends on:** 0.1 on PyPI, shared policy block.

### bastiontrace fuse landing

**What:** a landing kind for fuse trips (honeytoken in tool_call args, canary tool, taint-egress), so `bastiontrace analyze` scores snapshots.

**Why:** today a snapshot loads but scores "no landing" (D8).

**Effort:** S
**Priority:** P3
**Depends on:** none.

### Repeat detector promotion

**What:** after 20+ real sessions with 0 false trips at a tuned threshold, consider defaulting `repeat.action: enforce`. Record the tally in the CHANGELOG.

**Why:** heuristic detectors ship in shadow mode (suite rule).

**Effort:** S
**Priority:** P3
**Depends on:** dogfood.

### Interpreter-mediated egress

**What:** classify `python -c`, `node -e`, `bash -c "$(...)"` and scripts written then run. One option is to taint "wrote an executable file, then ran it" sequences.

**Why:** the biggest documented classification gap (README Limits).

**Effort:** M
**Priority:** P3
**Depends on:** dogfood data on false-positive cost.

## Other repos

- **agentbastion:** time windows for `rate_limits` (`{max, window_s}`). Fuse budgets show the shape (eng review OV8).
- **bastionprobe:** L5 "assume-breach" tier, scored by whether the fuse trips before the landing (release step 6).
