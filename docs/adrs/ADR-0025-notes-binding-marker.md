---
status: accepted
date: 2026-07-19
relates_to: ADR-0011 (notes bindings — amends its "dropped wrapper" decision), ADR-0018 §4 (bare-hostname shorthand), ADR-0021 (multi-host notes), ADR-0024 (notes host allowlist — complementary control)
---

# ADR-0025: Notes-binding marker — a note is only a binding when it says so

## Context

The notes/annotation channel (BWS `notes`, GSM `avp-binding` annotation) was parsed as a
*potential binding on every secret*. ADR-0011 deliberately dropped an explicit `binding:` wrapper
key so a note stays "human-pasteable in seconds"; ADR-0018 §4 went further with the bare-hostname
shorthand (a note that is just `api.example.com` binds with zero YAML).

The 2026-07-18 v0.8.0 release smoke caught what that costs. Real vaults keep **human
descriptions** in the notes field ("HackerOne API identifier", "GCP project ID", "AWS claude-pai
IAM user…"). Every such description entered the binding parser:

- Scalar descriptions became garbage hosts via the shorthand (fixed same-day by the
  hostname-shape gate, `_BARE_HOSTNAME_RE`).
- Worse, structurally: a description that parses as YAML with binding-ish keys (`host: rotate
  quarterly`) is judged a **malformed binding** — and per ADR-0011's fail-closed rule, a
  malformed note *excludes the same secret's file bindings*. Ambient prose in a vault field
  could — and did — silently un-broker the fleet. The daemon stayed healthy; injection died.

The root defect is not any single parse rule: it is that **an ambient free-text channel was
treated as carrying intent by default**.

## Decision

A note/annotation is parsed as a binding **only when its first non-blank line is exactly**:

```
# avp-binding
```

(`NOTES_MARKER` in `notes_binding.py`.) The marker line is stripped; the remainder parses under
the unchanged ADR-0011/0018/0021 grammar (bare hostname, or flat mapping).

1. **Unmarked note → `NoBinding`, always.** It is a description. It cannot bind, cannot be
   malformed, cannot exclude file bindings. File-tier bindings stand untouched.
2. **Migration self-diagnosis.** An unmarked note that *looks* host-shaped (bare FQDN, or a
   `host:`/`hosts:` line) logs a load-time warning naming the secret and the missing marker —
   a forgotten marker is a named condition, not a mystery outage.
3. **Marked = explicit intent → errors are LOUD.** Marker with an empty body, or a marked scalar
   that is not hostname-shaped, is `InvalidBinding` (fail-closed, audited) — the operator opted
   in and typo'd; silence would be the wrong kindness. The `_BARE_HOSTNAME_RE` gate stays as the
   second belt behind the marker.
4. **Uniform across sources.** BWS notes and the GSM `avp-binding` annotation follow the same
   contract. On GSM the marker is redundant with the annotation key — accepted: one contract,
   one parser, no source plumbing, and GSM shipped in this same release so no installed base
   breaks.
5. **North Star cost: one line.** "Add a secret, tag it with a host" becomes a two-line note —
   `# avp-binding` + the host. The marker doubles as documentation at the vault: anyone reading
   the secret sees the note is machine-consumed.

## Consequences

**Good**
- The incident class is structurally dead: prose can never bind, never fail-closed-shadow file
  bindings, regardless of future grammar growth.
- Complements ADR-0024: the **marker** defends against *accident* (ambient text parsed), the
  **allowlist** against *malice* (annotation-writer confused-deputy). Independent controls,
  independent failure modes.
- Marked-note errors surface loudly instead of silently binding or silently vanishing.

**Bad / accepted**
- **Breaking for existing unmarked note bindings** — they become inert (with a load-time warning)
  until the marker line is prepended. Ships in v0.8.0 with an upgrade note; the only pre-0.8.0
  notes-binding user population is this project's own fleet (one secret: `HF_TOKEN`).
- One more line of ceremony on the zero-config path.

## Rejected

- **Marker for BWS only, GSM exempt** (annotation key is already a namespace) — rejected for
  contract uniformity and to keep the parser source-blind.
- **A config knob to disable the marker requirement** — rejected; an opt-out would resurrect the
  incident class on exactly the installs least likely to understand the risk.
