# azwaf code review — 2026-08-12

Whole-codebase review of `main` @ `6416348`, run along two independent axes:

- **Standards** — does the code follow the repo's documented standards (`CLAUDE.md`, `README.md`, `Makefile` tooling) plus a baseline of Fowler code smells?
- **Spec** — does the code faithfully implement what `README.md` and `CLAUDE.md` say it does?

There is no formal spec, issue tracker, or `docs/` directory in this repo, so `README.md` and
`CLAUDE.md` served as the specification for the Spec axis.

Findings are kept on separate axes deliberately: code can follow every convention while
implementing the wrong thing, or do exactly the right thing while breaking conventions.
Merging the two lets one mask the other.

Status legend: `[ ]` open · `[x]` fixed · `[~]` partially addressed

---

## Triage summary

All numbered findings are closed, including the code half of S9. What remains
open is the P4 smell work, which the review framed as judgement calls rather
than defects.

| Priority | Item | Axis | Kind | Status |
| --- | --- | --- | --- | --- |
| P1 | S8 `copy` struct shadowing breaks `--dry-run` and hashes | Spec | code | fixed |
| P1 | S16 `delete custom-rule --dry-run` deletes for real (same shape as S8) | Spec | code | fixed |
| P1 | S15 `delete custom-rule` skips the documented auto-backup | Spec | code | fixed |
| P1 | S17 a failed blob upload discards the local backup | Spec | code | fixed |
| P1 | S4 aliases rejected by both `delete` subcommands | Spec | code | fixed |
| P1 | S2 `backup --container-url` alone is rejected (docs say it works) | Spec | code | fixed |
| P1 | S1 `copy --async` is a no-op | Spec | code | fixed |
| P1 | A3 `fmt.Errorf(fmt.Sprintf(...), funcName)` corrupts 5 error messages | Standards | code | fixed |
| P2 | S3 `get custom-rule --output` ignored | Spec | code | fixed |
| P2 | S10 90-rule limit unenforced on `copy` / `restore` | Spec | code | fixed |
| P2 | S9 exclusion warning uses wrong granularity | Spec | code | fixed |
| P2 | A4 / S12 debug `fmt.Printf` on stdout in `copy` | Standards | code | fixed |
| P2 | A5 `panic` in library code (4 sites) | Standards | code | fixed |
| P3 | S11 misleading `show policy` validation message | Spec | code | fixed |
| P3 | S13 `--debug` read but never registered | Spec | code | fixed |
| P3 | S14 inverted `Output: input.Quiet` | Spec | code | fixed |
| P3 | A1 / S6 documented priority enforcement doesn't exist | both | **doc** | fixed |
| P3 | A2 documented file responsibilities inaccurate | Standards | **doc** | fixed |
| P3 | S5 conditions-per-rule limit documented, never checked | Spec | **doc** | fixed |
| P3 | S7 `--quiet` documented as global, honoured by `backup` only | Spec | **doc** | fixed |
| — | C. Nil-pointer safety across five paths | Spec | code | fixed |
| — | D. Accessor layer for optional policy fields | Standards | code | fixed |
| P4 | A-B duplicated code (11 clusters) | Standards | code | **all collapsed** |
| P4 | A-B dead code / speculative generality | Standards | code | open |
| P4 | A-B primitive obsession, middle man, data clumps | Standards | code | open |

Three findings turned out to be wrong on inspection and are corrected in place
rather than acted on: **S2** (described as silent data loss; it was a hard
error), the suspected **ipv4/ipv6 copy-paste bug** under duplicated code (the
cited line is in the other function, where it is correct), and the field path
given for the **S15** fix. Each carries a note and a test demonstrating why.

## Standards axis

### A. Documented-standard breaches (hard)

- [x] **A1. Documented priority enforcement doesn't exist.** `CLAUDE.md` claimed "Custom Rule
  Priorities: *Enforces* ordering: Log 1000-1999, Allow 3000-3999, Block 5000-5999." Nothing
  enforces or reads these ranges. `LogNetsPriorityStart`, `AllowNetsPriorityStart`,
  `BlockNetsPriorityStart`, `LogNetsPrefix`, `MaxLogNetsRules`/`MaxBlockNetsRules`/
  `MaxAllowNetsRules` (`policy/policy.go:41-62`) have zero non-declaration references;
  `CustomPriorityStart` is taken unvalidated from callers (`policy/custom_rules.go:1174`). The
  only consumer, `policy/block.go`, was 68 lines of fully commented-out code, since deleted.
  *Fixed on the doc side — see "Documentation fixes applied". Enforcing it in code, or deleting
  the constants, remains open.*

- [x] **A2. Documented file responsibilities violated.** `CLAUDE.md` mapped `output.go` to
  "Formatting for CLI output" and `config/config.go` to config parsing.
  - `policy/output.go:51-145` (`GetRawPolicyCustomRuleByID`, `PrintPolicy`), `:147`
    (`computeAdler32`), `:1491` (`ListPolicies`) do session creation and Azure fetching inside
    the formatting file.
  - `session/config.go:13-51` is a verbatim copy of `config/config.go`'s `ReadFileBytes`,
    `FileConfig`, `LoadFileConfig`. Config parsing has two homes.

  *Doc now describes reality. Relocating the code remains open.*

- [x] **A3. `fmt.Errorf(fmt.Sprintf(...), funcName)` — broken error construction, five sites.**
  `policy/output.go:138`, `policy/policy_managed.go:506`, `:569`, `:705`, `policy/stats.go:78`.
  The message is fully formatted by the inner `Sprintf`, so `funcName` becomes a surplus
  argument and Go appends `%!(EXTRA string=...)` to the user-visible error. The wrapped
  call-site context is lost.

  *Fixed at all five sites, each rewritten as `fmt.Errorf("%s - <message>", funcName, args...)`
  to match the convention used elsewhere in the package. The `output.go` site now wraps the
  marshal error with `%w` instead of flattening it through `.Error()`, and its "marshall" typo is
  normalised. No test asserted any of these strings. A repo-wide AST scan confirms zero remaining
  occurrences; the only other match is inside the dead comment block at
  `policy/policy_managed.go:412-475`, which the dead-code item still covers.*

  *Covered two ways. `TestGetPolicyStatsErrorNamesItsCallerAndHasNoFormatNoise` drives the one
  site reachable without a session seam — `getPolicyStats` is a pure function — and asserts the
  error names its caller and carries no `%!` noise; reverting that site produces
  `...Microsoft_DefaultRuleSet_2.1%!(EXTRA string=policy.getPolicyStats)`, exactly what users
  saw. The other four sit inside `ShowManagedRule*Exclusions`, which build their own session, so
  rather than test the remaining sites individually `TestNoErrorfWrappingSprintf` walks the
  package AST and fails on any `fmt.Errorf` whose format string is a `Sprintf` call — it
  pinpointed `stats.go:78:18` when checked against a reverted site. This shape is invisible to
  `go vet`, because the format string is not a constant it can analyse, so the guard is what
  keeps it from returning.*

- [x] **A4. Debug `fmt.Printf` in production paths.** `policy/copy.go:192-198` prints four
  `%#+v` dumps of policy internals on every managed-rule copy. The repo has a dedicated
  `logging` package driven by `AZWAF_LOG`.

  *Fixed: the five prints (four in the managed-rules branch, one in the default branch, two of
  them exact duplicates of each other) are replaced by one `logging.Debugf` per branch. The
  detail they carried is still available under `AZWAF_LOG=debug`, on the library's own logger
  rather than stdout. `copy.go` now contains no `fmt.Print*` at all. Every other `fmt.Print*` in
  the package is legitimate CLI rendering — `show` tables, the confirmation prompt, backup
  progress — and was left alone.*

  *Covered by `TestCopyRulesWritesNothingToStdout`, which redirects `os.Stdout` across all three
  copy modes and asserts nothing is written, and `TestCopyRulesLogsDetailAtDebugLevel`. Restoring
  the prints fails the managed-rules subtest with the raw
  `armfrontdoor.WebApplicationFirewallPolicyProperties{...}` dump as the failure message — which
  is what users piping `copy` output were getting mixed into their data.*

  *Note the source and target fixtures had to be made genuinely different in both their custom
  rules and their managed-rule exclusions: with identical policies `CopyRules` short-circuits on
  "rules are already identical" and never reaches this code, which would have made the test
  vacuous. The test asserts a push happened to prove the copy actually ran.*

- [x] **A5. `panic` in library code**, against the direction of the recent "remove library Fatal
  calls" work (`e788ac2`): `policy/output.go:204`, `:314`, `policy/policy_managed.go:87`,
  `session/session.go:110`. The last also panics with an unformatted format string,
  `panic("%s called with null session")`, so the literal `%s` reaches the user.

  *Fixed at all four sites, each according to what the caller can actually do:*
  - *`session.go:110` — a nil receiver is now logged via `logging.Errorf` and returns. The
    unformatted format string is fixed at the same time. No signature change: the three callers
    are internal and `s` is non-nil by construction there, so the check is purely defensive.*
  - *`policy_managed.go:87` — `getMatchingDefaultDefinitions` now returns an error. Both callers
    already nil-checked the result and reported a vaguer downstream miss, so they now surface the
    precise precondition failure instead.*
  - *`output.go:203` — `formatRuleEnabledState` returns `"-"` rather than panicking. This was
    genuinely reachable: `PrintPolicyCustomRule` (`output.go:1049`) passes `"-"` as the default,
    so **any** rule state the code did not recognise took the process down mid-table.*
  - *`output.go:313` — a nil `NegateCondition` renders as `"-"`, matching the `valueOrDash`
    convention used by every neighbouring cell.*

  *Covered by `TestFormatRuleEnabledStateHandlesUnknownStates`,
  `TestOutputCustomRuleMatchConditionsToleratesNilNegate`,
  `TestGetMatchingDefaultDefinitionsRequiresRuleSetDetails` and, in the session package,
  `TestInitialiseCacheOnNilSessionDoesNotPanic`. All fail when the panics are restored. Two AST
  guards — `TestNoPanicsInPolicyPackage` and `TestNoPanicsInSessionPackage` — fail on any `panic`
  reaching non-test code; against the restored versions they report
  `[output.go:204:3 output.go:315:4 policy_managed.go:87:3]`. No `panic` remains in any
  non-test file.*

  *Separately noted, not fixed: `appendCustomRuleRows` (`policy/output.go:269-287`) dereferences
  `cr.Name`, `cr.EnabledState`, `cr.Priority` and `cr.RuleType` unguarded, and will nil-panic on a
  policy missing any of them. Found while building the fixture for the negate-condition test.
  That is a nil-safety issue rather than an explicit `panic` call, so it sits outside A5.*

### C. Nil-pointer safety (added during the fix pass)

- [x] **Unguarded dereferences of optional API fields.** Policy fields arriving from the Azure
  SDK are pointers, and the rendering and push paths dereferenced several without a check, so a
  policy missing any one of them crashed the process rather than showing a dash. Found
  incrementally while building test fixtures for A5, S10 and the sort de-duplication, then swept
  together. Seven sites fixed:

  | Site | Field(s) | Reached by |
  | --- | --- | --- |
  | `valueOrDash` (`output.go:1189`) | `*MatchVariable`, `*Operator` | any table render — **the "safe" helper was itself unsafe** |
  | `appendCustomRuleRows` (`:269`) | `Name`, `EnabledState`, `Priority`, `RuleType` | `show policy` |
  | `OutputPolicyMetaData` (`:1046`) | `ID`, `SKU.Name`, `Properties`, `PolicySettings` | `show policy` |
  | `outputManagedRulesets` (`:607`) | `SKU.Name` | `show policy` |
  | `showFrontDoors` (`:215`) | `wafPolicy.Name` | `list frontdoors` |
  | `sortCustomRulesByPriority` (`custom_rules.go`) | `Priority` | any custom-rule sort |
  | `PushPolicy` (`data.go:94`) | `Policy.Name` | every push |

  *Each renders `-` or an empty value now, matching the `valueOrDash` convention already used by
  neighbouring cells; the sort treats a missing priority as 0 so it sorts first deterministically;
  `PushPolicy` logs the name it was passed rather than the one on the policy body. The
  `format*` helpers were already nil-safe, so `OutputPolicyMetaData` substitutes empty
  `Properties`/`PolicySettings` structs and lets them do their job rather than repeating the
  checks.*

  *Covered by `policy/nilsafety_test.go` — 18 cases across the seven sites, every one of which
  panicked before the fix. Existing output tests still pass unchanged, so well-formed policies
  render exactly as before.*

- [x] **Same sweep across the `copy` and `restore` paths.** Probed by driving the internal
  functions with policies missing each optional container and recording which panicked: eight of
  twelve cases did. Two more sites fixed:

  - *`copyPolicyRules` (`copy.go:179`) — `source.Properties` and `target.Properties` were
    dereferenced unguarded. **The nil-target check was also unreachable**: it sat as a later arm
    of the same switch as the managed-rules check, so once `customRulesOnly || !managedRulesOnly`
    matched, `case target == nil` never ran and a nil target panicked instead of erroring. The
    nil checks are now plain `if` statements ahead of the switch, which is what made the ordering
    bug visible.*
  - *`BuildRestoredPolicy` (`restore.go`) — chained up to four optional pointers per assignment
    (`copyOfOriginalPolicy.Policy.Properties.CustomRules.Rules = backup.Policy.Properties.CustomRules.Rules`).
    Three small helpers — `ensurePolicyProperties`, `backupCustomRules`, `backupManagedRules` —
    now carry the nil handling, and the managed-rules arm collapses to one line. A backup holding
    no rules clears the target's rather than leaving stale ones behind, matching what the
    managed-rules arm already did explicitly.*

  *`BuildRestoredAppGWPolicy` was probed the same way and is already nil-safe — it guards
  `existing.Policy.Properties` and reads the backup defensively — so it was left alone.*

  *Covered by 13 further cases in `policy/nilsafety_test.go`, including one asserting the
  clear-on-empty-backup behaviour rather than just the absence of a panic.*

- [x] **Same sweep across the exclusion paths.** The densest area: these helpers walk deeply
  nested API structures — rule sets hold group overrides, which hold rules, which hold exclusions
  — and dereferenced names and identifiers at every level. Probed the same way: **19 of 26 cases
  panicked**. Guards added across `policy_managed.go`, `delete_managed_exclusion.go` and
  `add_exclusions.go`, covering `getRuleGroupExclusionsFromRuleSet`, `getAllExclusionsByRuleID`,
  `getShadowsFromRuleSet`, `HasMatchingExclusions`, `getRuleSetStats`, `getMatchingRuleSet`,
  `getDefinitionMatchingExistingRuleSet`, `getRuleSetDefinitionMatchingRuleSetTypeVersion`, the
  `strip*` family, `matchManagedRuleGroupOverrideExclusion` and `addToManagedRuleSet`. A
  `derefOrEmpty` helper carries the repeated optional-string reads.

  *Two things beyond nil-guarding turned up:*
  - *`stripManagedRuleGroupOverrideRules` read `newManagedRuleOverride.Exclusions` **outside**
    the `if newManagedRuleOverride != nil` check immediately above it — a latent panic the
    author had already half-guarded against. The count comparison now sits inside the check.*
  - *`getShadowsFromRuleSet` survived the first pass and was caught only because the permanent
    test used a stricter fixture than the probe, with `nil` entries in the slices rather than
    just nil fields. Worth remembering: nil elements and nil fields are different failure modes.*

  *Covered by 23 further cases in `policy/nilsafety_test.go`.*

  **Coverage.** The `policy` package contains roughly 400 pointer dereferences. The render, push,
  copy, restore and exclusion paths are now swept — that is the bulk of the code that handles API
  data. What remains unswept is mostly the IP-nets library API in `custom_rules.go`, which has no
  CLI entry point, plus assorted small helpers.

### D. Accessor layer for optional policy fields

- [x] **Optional-pointer chains centralised behind accessors** (`policy/accessors.go`). The four
  nil-safety sweeps above each fixed crashes by adding guards at the site, which stopped the
  panics without stopping the *pattern*: the next function to walk
  `Policy → Properties → CustomRules → Rules` by hand would make the same assumption. The
  accessors do the checking once; ranging over the nil slice they return is a no-op, so callers
  read straight through.

  **A normalising layer was considered and rejected.** Filling empty containers into the fetched
  policy would have been simpler for callers, but `GeneratePolicyPatch` (`policy.go:667`) diffs
  by marshalling both sides to JSON, where an absent container and an empty one are not equal.
  Mutating the policy would therefore invent differences — and every mutating command gates on
  `patch.TotalDifferences == 0`, so azwaf would push when nothing had changed — as well as
  altering what is sent to Azure and what auto-backups contain. Read-only accessors get the same
  centralisation with none of that exposure.

  *34 call sites migrated across 10 files. Two further latent bugs surfaced while migrating:*
  - *`custom_rules.go:807` checked `in.Policy.Properties == nil` **after** the line above had
    already dereferenced `Properties`, so it could never fire. The accessor covers that case and
    errors earlier; the dead check is gone.*
  - *`getDefaultRuleSet` (`output.go`) indexed the rule-set slice and dereferenced
    `*RuleSetType` per entry with no nil handling on either.*

  *Enforced by `TestPropertyChainsGoThroughAccessors`, which fails the build on any read of a
  `Properties.CustomRules` / `Properties.ManagedRules` chain outside `accessors.go`. Writes are
  exempt — assigning through the chain is how a policy is updated and an accessor cannot express
  that — as is `appgw_restore.go`, which models the separate Application Gateway type tree and
  was verified nil-safe on its own. Verified by reintroducing a chain in `stats.go`, which the
  guard reports as `stats.go:69:21`. This matters because convention alone has already failed
  once in this package: `valueOrDash`, the helper whose job was nil-safety, was itself unsafe.*

  *`TestAccessorsReturnEmptyForAbsentLevels` and `TestAccessorsReturnPopulatedValues` cover the
  accessors themselves; the 59 nil-safety cases from the sweeps all still pass unchanged, which
  is what establishes the refactor changed no behaviour.*

  **Scope.** Accessors cover the *containers*. Nil entries within a returned slice are still
  skipped by callers individually, and optional leaf fields — `Name`, `Priority`, `RuleID` —
  are still read through `derefOrEmpty` or `valueOrDash`, because absent genuinely means the API
  sent nothing.

### B. Baseline smells (judgement calls)

- [ ] **Duplicated code** — the dominant smell:
  - ~~`sortRulesByPriority` (`policy/custom_rules.go:739`) and `sortCustomRulesByPriority`
    (`:990`) are identical.~~

    *Confirmed identical — byte for byte apart from the parameter name — and collapsed.
    `sortCustomRulesByPriority` survives: it is the more accurate name for a
    `[]*armfrontdoor.CustomRule`, and already had a test. Its two call sites at `:714-715` were
    repointed and `sortRulesByPriority` deleted. No characterisation test was needed here, unlike
    the IP-handler merge: with two identical implementations there is no behaviour that could
    differ between them, so the existing `sortCustomRulesByPriority` test and the full suite are
    the verification.*

    *Noted, not fixed: the comparator dereferences `*rules[i].Priority` unguarded, so a custom
    rule with no priority panics mid-sort. Same nil-safety class as the `appendCustomRuleRows`
    and `PushPolicy` derefs recorded elsewhere.*
  - ~~`DeleteCustomRulesCLIInput.ProcessCLIInput` (`policy/delete_managed_exclusion.go:32`) and
    `.ParseConfig` (`policy/delete_custom_rule.go:75`) are identical methods on the same type.~~

    *Confirmed byte-identical apart from the method name, with `ProcessCLIInput` having no caller
    anywhere — including `it/`, which is behind a build tag and so invisible to `go build ./...`.
    Deleted. It was the only user of the `regexp` and `strconv` imports in that file, which went
    with it.*
  - ~~`BackupPolicy` (`policy/backup.go:227`) vs `BackupAppGWPolicy` (`:365`) — ~90% identical,
    as are `backupPolicies` / `backupAppGWPolicies`.~~

    *Both now delegate to `backupWrapped`, with the per-type differences — the default WAF type
    and the word used in the status line — carried by a `prepareForBackup` method behind a
    `backupSubject` interface. Exported signatures are unchanged. The duplicated terminal-width
    status line became `printBackupStatus`, and the five arguments that travelled together
    became a `backupDestination` struct, which also settles the data-clump item below. Close to
    line-neutral: the gain is one place to change, not fewer lines. `backupPolicies` /
    `backupAppGWPolicies` are the thin loops over each and remain separate.*
  - `handleIPv4Value` (`policy/output.go:1218`) vs `handleIPv6Value` (`:1287`) — 135
    near-identical lines. ~~**`:1280` sets `*prevType = "ipv4"` inside the ipv6 branch** — likely
    a copy-paste bug worth checking on its own.~~

    *Checked: **not a bug, this finding was wrong.** `:1280` sits inside `handleIPv4Value`, not
    `handleIPv6Value` — the review's own line numbers put `handleIPv6Value` at `:1287`, seven
    lines later. The branch in question is the `case "ipv6":` arm *of* `handleIPv4Value`, i.e.
    "an IPv4 value following an IPv6 one", where setting `prevType` to `"ipv4"` is exactly
    right: it names the value just written. `handleIPv6Value` sets `"ipv6"` in all four of its
    branches. The duplication between the two functions is real and still worth collapsing; the
    defect is not.*

    *The duplication itself is now gone: `handleIPv4Value` and `handleIPv6Value` are replaced by
    a single `handleIPValue` taking the family as a parameter, with the inline write factored
    into `writeIPValueInline` — 138 lines down to 49. The magic `"ipv4"`/`"ipv6"` strings are now
    `ipTypeV4`/`ipTypeV6` constants.*

    *One subtlety made this more than a mechanical merge. The empty-`prevType` case looks like it
    should fold in with the others, but `handleURLValue` clears `prevType` without resetting
    `valsWritten`, and `handleGeoValue` moves `valsWritten` without touching `prevType` — so a
    value can arrive with a line already part-written, and the original put it inline regardless.
    Folding the case in changes where lines break. `TestWrapMatchValuesFormatting`, a
    characterisation test capturing the two-function output across eight inputs first, catches
    exactly that: the naive version fails `geo mixed` with
    `"GB, US, 10.0.0.1/32\nFR, ..."` against the expected single line. The kept version passes
    all eight unchanged.*

    *Verified rather than argued: `TestIPValueHandlersTrackPrevTypeCorrectly` drives both
    handlers across all three incoming `prevType` states and asserts the resulting state names
    the type just written, and `TestIPValueHandlersResetPrevTypeOnLineBreak` covers the
    line-break reset — ten cases, all passing against unmodified code. Injecting the
    hypothesised bug into `handleIPv6Value` makes `ipv6/after_ipv4` fail with "after writing an
    ipv6 value prevType must be "ipv6"", so the tests would catch it if it were ever
    introduced.*
  - ~~`GetDeleteManagedRuleExclusionProcessScope` (`policy/policy_managed.go:804`) vs
    `GetAddManagedRuleExclusionProcessScope` (`:840`) — the same if-cascade twice.~~

    *Collapsed onto `scopeFromSelectors`. The wrappers keep their own error wording and failure
    return — the delete side returns `""`, the add side `"unhandled"` — so callers see no change.
    The cascade also simplified: four overlapping conditions reduce to three once the earlier
    branches have already excluded the cases they overlap on.*

    ***This one was not just duplication.*** *Both functions dereferenced an optional
    `*string` rule set unguarded. The delete side checked it for nil once, then dereferenced it
    anyway two lines later, so a group-scoped delete with no rule set panicked. The add side
    dereferenced both `RuleSetType` and `RuleSetVersion` before checking anything at all, so it
    panicked on an empty input. Three cases were confirmed panicking before the change and pass
    after it. The existing test covered only the delete side, and only combinations where the
    pointer happened to be set.*
  - ~~`GetPolicyResourceIDByHash` / `GetPolicyRIDByHash` (`policy/policy.go:189` / `:226`)~~
    *— collapsed. The first was the second with `config.ParseResourceID` applied, duplicating the
    cache read, the policy fetch and the hash-map save. It is now a wrapper, 36 lines down to 11.
    Neither had any test, so the cache path, the agreement between the two return shapes and the
    unknown-hash error were pinned first.*;
    ~~`marshalPolicy` / `marshalAppGWOriginal`~~ *— merged into `marshalOriginal`. See the note
    below on what that trades*;
    ~~`getIPNetsForPrefix` / `getIPNetsForRuleIPMatchConditions`~~ and
    ~~`rebuildIPMatchConditions` / `prepareMatchConditions`~~ *— the last IP-nets pair, collapsed
    onto `ipNetsFromRule` and `matchConditionsFromNets`; 91 lines removed against 67 added. Both
    pairs hid a defect, described below*;
    ~~the four client getters in `session/clients.go`~~ *— collapsed onto a generic
    `getOrCreateClient`, 136 lines removed against 54 added. See the note below on what it
    normalised*; ~~the diff-via-temp-file logic in
    `policy/output.go:1401` vs `policy/compare.go:18`~~ *— both now go through `diffTempFiles`.
    The two still differ in what they do with the result, which is the point: `compare` only
    reports whether there was a difference and prints nothing, while
    `DisplayStringDiffWithDiffTool` prints the diff. The display side also swallowed any failure
    to **run** diff — a non-`ExitError` left the exit code at zero and it returned nil — where
    `compare` surfaced it. It now surfaces it too. Removing the duplicated block orphaned three
    imports in `output.go`, one of which was the `errors2` alias listed under mysterious names
    below, so that is gone as well.*

  *Note on the IP-nets pair. Neither collapse was cosmetic; both differences turned out to
  matter.*

  *The two collectors walked the same match conditions and split them the same way, differing
  only in what an unsupported (non-IP) condition meant: `getIPNetsForPrefix` refused the whole
  rule, `getIPNetsForRuleIPMatchConditions` skipped it. That difference is deliberate and is
  preserved as the `skipUnsupported` argument to `ipNetsFromRule` — the skipping caller reads an
  existing rule whose non-IP conditions are carried over separately by `getNonIPMatchConditions`,
  while the erroring caller is building a rule from scratch and cannot represent a mixed one.
  Both dereferenced `NegateCondition` and each `MatchValue` unguarded, the same nil-panic class
  swept elsewhere in this review; a condition with no negate flag set panicked, confirmed before
  the change. An absent flag now reads as not negated, and a nil match value becomes an empty
  string that fails prefix parsing with an error rather than a panic. The unused
  `action *armfrontdoor.ActionType` parameter is nil-checked and then never read — that is
  unchanged, since it is part of an exported-adjacent signature and removing it is a separate
  call.*

  *The two generation tails were identical apart from one guard. `prepareMatchConditions`
  rejected a negated set of 599 or more; `rebuildIPMatchConditions` did not, and needed it just
  as much. Every generated rule repeats the entire negated set, so the positive budget is
  `MaxIPMatchValues - len(negated)`. Once that reaches zero the chunker stops splitting — it
  flushes early only when a chunk **reaches** its budget, and a chunk holding at least one entry
  never equals zero — so it emits a single positive condition holding every net. Measured on the
  old code: 600 negated plus 2000 positive nets returned no error and one match condition with
  2000 values, more than triple Azure's 600-per-condition maximum. The shared
  `matchConditionsFromNets` applies the guard to both, so that input now errors. The literal
  `599` is expressed as `MaxIPMatchValues-1`, which is the same number and says why.*

  *Note on `marshalOriginal`: the two it replaced were the same switch over **disjoint** type
  sets — Front Door types in one, Application Gateway in the other — so merging them widens what
  each caller will accept. In principle a Front Door diff could now be handed an AppGW policy and
  marshal it rather than erroring. Judged acceptable: both were unexported with a single call
  site each, and both call sites pass a concrete type, so the split was not buying safety the
  compiler was not already providing. If that type discipline is wanted back, the two thin
  wrappers are cheap to reinstate over the shared switch.*

  *Note on the client getters: the four had drifted, and the duplication was hiding it. None
  applied the same guards:*

  | Getter | nil session | empty subscription id | retry/telemetry options |
  | --- | --- | --- | --- |
  | `GetFrontDoorPoliciesClient` | yes | no | yes |
  | `GetAppGWPoliciesClient` | yes | yes | yes |
  | `GetManagedRuleSetsClient` | no | yes | no |
  | `GetFrontDoorsClient` | no | no | no |

  *Collapsing normalised all three columns, which is a behaviour change in three ways: two
  getters return an error on a nil session where they previously panicked; two reject an empty
  subscription id where they previously built a client that could never work; and two now get the
  3-retry, 30-second-max-delay, telemetry-tagged options the other two already had, in place of
  SDK defaults. The last is the one to be aware of — it changes how those two clients behave
  against Azure — but the divergence looked accidental rather than designed. Error text now names
  the client kind rather than the Go function; nothing asserted the old wording.*

- [ ] **Speculative generality / dead code** — declared, never used outside their own
  declaration: `LoadBackupsFromPaths` + `LoadBackupsFromPath` (`policy/data.go:202`, `:225`,
  superseded by `LoadAllBackupsFromPaths`), `BotRuleSetStatsOutput`, `LogIPsInput`,
  `WrappedManagedRuleSet`, `Action`, `MaxConditionsPerCustomRule`, `errPolicyNotDefined`,
  `errInvalidMatchVariable`, `defaultRuleSetPrefix`, `botManagerRuleSetPrefix`, `actionAllow`,
  `NewResourceID`, `SetSubscriptionID`. `OutputManagedRuleExclusionsTableInput.ruleDefinition/
  groupDefinition/setDefinition` (`policy/output.go:892-894`) and six `OutputManagedRuleInput`
  fields are populated at every call site and read nowhere. Whole-file dead comment blocks:
  ~~`policy/block.go` (all 68 lines), `policy/restore.go:30-96`,
  `policy/policy_managed.go:412-475`.~~

  *All three deleted. `block.go` was nothing but comments and a package declaration: it
  contributed no symbol and was referenced nowhere. The other two were a commented-out
  `restorePolicy` (67 lines, superseded by the active restore path) and a commented-out
  `ShowManagedRuleExclusionShadows` (64 lines). Neither had an active counterpart. 199 lines in
  total.*

  *Deleting `block.go` also settled the status of the constants in A1: it had stood as their
  notional consumer, and with it gone `LogNetsPriorityStart`, `AllowNetsPriorityStart`,
  `BlockNetsPriorityStart`, `LogNetsPrefix`, `MaxLogNetsRules`, `MaxBlockNetsRules`,
  `MaxAllowNetsRules` and `MaxConditionsPerCustomRule` have no reference beyond their own
  declarations. They are **exported**, so removing them would break any library consumer — left
  as a deliberate open decision rather than swept up. `actionAllow` is unexported and equally
  unused; `actionBlock` reads as dead by the same argument but is genuinely used at
  `custom_rules.go:336`.*

  *The unexported dead declarations are now removed: `errInvalidMatchVariable`,
  `defaultRuleSetPrefix`, `botManagerRuleSetPrefix` and `actionAllow`, plus the
  `ruleDefinition` / `groupDefinition` / `setDefinition` fields on
  `OutputManagedRuleExclusionsTableInput`, which were assigned at all three call sites and never
  read — nine assignments went with them.*

  *Two corrections to this finding while checking. `errPolicyNotDefined` is **not** dead:
  `TestGetPolicyStatsWithoutPolicy` asserts against it, so the original list was counting
  non-test references only. `actionBlock` reads as dead by the same argument the finding uses
  but is genuinely used at `custom_rules.go:336`.*

  *The exported ones were then removed too, on the owner's decision. The module is at v0.4.0, so
  semver permits it. Gone: `BotRuleSetStatsOutput`, `LogIPsInput`, `WrappedManagedRuleSet`,
  `Action`, `SetSubscriptionID`, the eight constants orphaned by deleting `block.go`, and five
  never-read fields on `OutputManagedRuleInput` — the last taking fifteen assignments with them,
  three of which walked `Properties.PolicySettings` unguarded and were latent nil panics.*

  *Two required more than deletion. `LoadBackupsFromPaths` and `LoadBackupsFromPath` were unused
  by production code but loaded fixtures for fourteen tests; they moved into the test package as
  `loadBackupsFromPathsForTest`, wrapping the superseding `LoadAllBackupsFromPaths`, which takes
  them out of the public surface without churning the call sites. `NewResourceID` was **kept**:
  it is used by `it/policy_integration_test.go`, which sits behind a `//go:build integration`
  tag, so `go build ./...` and `go vet ./...` do not see it and removing it would have broken
  the integration suite silently. Every candidate was checked against `it/` for that reason, and
  the suite was compiled with `-tags integration` afterwards.*

  *The scattered fragments are done too, judged one at a time rather than swept. The earlier
  count of "five to sixteen lines across seven files" was inflated: the pattern used to find them
  matched ordinary prose beginning `// if ...`, and the genuine commented-out code sat in five
  files, not seven.*

  *Deleted as refactor leftovers: an old function signature and an old call form in
  `delete_custom_rule.go`, sitting directly above their replacements; a dead
  `StripCustomRulesPrefixes` wrapper; an abandoned error return in `custom_rules.go` whose
  behaviour the `continue` above already states; and a commented `originalTargetPolicy` block in
  `copy.go`.*

  *Three carried real open questions, so the question was kept as prose and only the code
  dropped: whether passing no exclusion criteria should strip all exclusions or none
  (`delete_managed_exclusion.go`), and the default-deny warning, whose commented implementation
  spanned `output.go` and `policy_checks.go`. That pair could never have been uncommented as
  written — it called `logrus`, dropped in the slog migration, and a `HasDefaultDeny` that was
  itself commented out. It also read the enabled state inverted, which the replacement TODO
  records.*

  *`CustomRuleHasDefaultDeny` was **kept** despite having no production caller once
  `HasDefaultDeny` went: it is exported, has real tests, and is the building block the remaining
  TODO needs.*

- [ ] **Primitive obsession / repeated switches** — `scope` is a bare `string`
  (`ScopeRule`/`RuleGroup`/`RuleSet`) switched on in `policy/policy_managed.go:356`,
  `policy/add_exclusions.go:248`, `policy/delete_managed_exclusion.go:98`, `:392`,
  `policy/output.go:663`. Likewise `prevType string` carrying `"ipv4"`/`"ipv6"`/`""` through
  `policy/output.go`. Both want small named types.

- [ ] **Middle man** — `WrappedAppGWPolicy.toFDLikeBackup` (`policy/appgw_restore.go:213`)
  purely delegates to `dummyWrappedFromAppGW`; `policy.GetFunctionName` (`policy/utils.go:112`)
  just calls `helpers.GetParentFunctionName`.

- [ ] **Mysterious names** — `dummyWrappedFromAppGW`; ~~the `errors2` import alias
  (`policy/output.go:5`)~~ *— gone, orphaned by the diff collapse*; `getIPNetsForPrefix` takes no
  prefix; ~~`ProcessCLIInput` vs `ParseConfig` naming the same operation~~ *— `ProcessCLIInput`
  deleted*.

- [ ] **Data clumps** — `(blobClient, containerName, failFast, quiet, path)` threaded
  positionally through five backup functions despite `BackupPoliciesInput` already existing.

---

## Spec axis

### (a) Documented but missing / not enforced

- [x] **S1. `copy --async` is a no-op.** `README.md` — "`--async` … Push without waiting for
  completion". Parsed at `cmd/commands/cmdCopy.go:40` into `policy/copy.go:28`, then dropped:
  `CopyRules` → `ProcessPolicyChanges` (`policy/copy.go:132-142`) → `PushPolicy`
  (`policy/policy.go:724-730`) never sets `PushPolicyInput.Async` (`policy/data.go:82`). The
  `if i.Async` branch at `policy/data.go:109` is unreachable from the CLI.

  *Fixed by threading the flag the last two hops: `ProcessPolicyChangesInput` gained an `Async`
  field, `ProcessPolicyChanges` forwards it to `PushPolicyInput.Async`, and `CopyRules` passes
  its own `i.Async`. The `if i.Async` branch in `PushPolicy` was already correct and needed no
  change — this was purely missing wiring. `copy` is the only command with an `--async` flag, so
  every other push path passes false and keeps waiting.*

  *The fakes record the push on `BeginCreateOrUpdate` regardless of polling, so the two paths are
  told apart by what they log: `asynchronous policy push started` versus `policy <name> updated`.
  Covered by `TestCopyRulesAsyncDoesNotWaitForCompletion`,
  `TestCopyRulesWithoutAsyncWaitsForCompletion` and `TestDeleteCustomRuleIsNotAsync` (a command
  with no `--async` flag must still wait). The first fails without the wiring.*

  *`README.md` already described the flag correctly, so no doc change was needed.*

- [x] **S2. `backup --container-url` alone is rejected.** `README.md` showed `--container-url`
  used on its own and listed `--storage-account-id` as "an alternative" to it. Neither worked.

  *The original finding here was wrong and is corrected: this was never silent data loss.*
  `policy/backup.go:81` carried a mutual-requirement guard, so **either flag used alone returned
  a hard error** — `both storage account resource id and container url are required for backups
  to Azure Storage`. Verified against the fakes before changing anything. The real defect was a
  spec mismatch: the tool demanded both flags while the docs presented them as alternatives.

  *Fixed by making a container url self-sufficient, which is what the README's primary example
  shows. Blob-client construction moved into `newBackupBlobClient` (`policy/backup.go:164`):*
  - *container url alone → the account (host) and container (path) come from the url, and the
    session's `azcore.TokenCredential` authenticates; the caller needs a blob data role.*
  - *container url + storage account id → unchanged shared-key path via ARM `ListKeys`, for
    callers without that role.*
  - *storage account id alone → still an error, now an accurate one: nothing names the
    container. `README.md` no longer claims this form works.*

  *`URLParts.Scheme` is documented as `"https://"` but returns `"https"`; concatenating blind
  produced `httpsmyacc.blob.core.windows.net/`. The test caught it — the service url is now
  built with `TrimSuffix` + `Sprintf`.*

  *Covered by `TestNewBackupBlobClientAcceptsContainerURLAlone` (asserts the resulting
  `client.URL()`), `...WithoutDestination`, `...RejectsStorageAccountWithoutContainer`,
  `...RejectsMalformedContainerURL`, `TestBackupPoliciesAcceptsContainerURLAsOnlyDestination`
  and `TestBackupPoliciesRequiresADestination`. The last fails against the old guard.*

- [x] **S17. A failed blob upload discards the local backup.** Found while testing S2.
  `policy/backup.go:332` returns the `UploadBuffer` error unconditionally, ignoring `failFast` —
  unlike the marshal error a few lines above, which respects it. Because the local write at
  `:337` comes *after* the upload, any upload failure skips it entirely, and `backupPolicies`
  then swallows the error when `failFast` is false. So `azwaf backup --path ./b --container-url
  https://…` against an unreachable container exits 0 having written **nothing at all**, despite
  `README.md` offering blob storage "alongside or instead of local disk". `BackupAppGWPolicy`
  (`:418-430`) had the same shape. This is the silent data loss the original S2 was reaching for.

  *Fixed: both backup functions now write locally **before** uploading, and the upload moved into
  a shared `uploadBackupToContainer` (`policy/backup.go`) that honours `failFast` — returning a
  wrapped `failed to upload` error when set, logging and continuing when not. The local copy is
  the cheaper and more reliable destination, so it is no longer hostage to the remote one. This
  also removes one of the review's duplicated-code clusters between `BackupPolicy` and
  `BackupAppGWPolicy`.*

  *Covered by `TestBackupPoliciesWritesLocallyWhenUploadFails` (a mixed FD + AppGW backup with a
  failing container still lands both files on disk) and
  `TestBackupPoliciesFailFastSurfacesUploadErrorAfterLocalWrite`. Both fail against the old
  ordering — the first with `"[ApplicationGateway]" should have 2 item(s), but has 1`, which is
  the bug exactly: the Front Door local write was lost to the failed upload.*

  *The upload tests use a local `httptest` server rather than a real or `.invalid` host: the
  former would send requests to a third party's storage endpoint, and the latter cost 41s in SDK
  retry backoff. Against the local server the credential refuses to send a bearer token over
  plaintext http, which fails the upload in ~2ms with no network egress.*

- [x] **S3. `get custom-rule --output` is ignored.** `README.md` —
  `azwaf get custom-rule "prod-waf|BlockBadActor" --output rule.json`. The flag is declared at
  `cmd/commands/cmdGet.go:33` and never read; the action calls
  `PrintPolicyCustomRule(sub, input, config)`, whose signature (`policy/output.go:78`) has no
  output path. Output always goes to stdout.

  *Fixed: `PrintPolicyCustomRule` now takes a `PrintPolicyCustomRuleInput` struct rather than a
  fourth positional string — the three it already had were the review's own primitive-obsession
  smell, and a fourth would have compounded it. With `OutputPath` set the rule is written there
  and a confirmation is logged (suppressed by `--quiet`); without it the rule still goes to
  stdout, so piping into `jq` is unchanged. Write failures are reported rather than swallowed.
  `cmd/commands/cmdGet.go` now reads the flag it was already declaring, and a `Session` seam was
  added.*

  *Covered by `TestPrintPolicyCustomRuleWritesToOutputPath` (file written, stdout empty),
  `...WithoutOutputPathPrints` (stdout still parses as the rule),
  `...ReportsUnwritableOutputPath` and `...ResolvesAlias`. Three of the four fail against the
  old stdout-only behaviour.*

- [x] **S4. Aliases don't work for either `delete` subcommand.** `README.md` lists an alias as
  one of three universal ways to name a policy. `cmd/commands/cmdDelete.go:65` and `:126` call
  `ValidateResourceID(input, false)` on the raw argument *before* alias resolution; an alias
  contains no `/`, so `policy/validation.go:165` rejects it. The custom-rule path silently
  prints help rather than erroring. Additionally `DeleteManagedRuleExclusion`
  (`policy/delete_managed_exclusion.go:462-478`) never calls `GetWAFPolicyResourceID`, and
  `cmd/commands/cmdDelete.go:80-94` never populates `ConfigPath`.

  *Fixed in three layers. `GetWAFPolicyResourceID` (`policy/policy.go:265`) already resolves and
  validates all three naming forms, so it is now the single front door:*
  1. *CLI: the `ValidateResourceID` pre-check and the duplicated hash-needs-subscription check
     (which restated `GetWAFPolicyResourceID:294`) are gone from both subcommands, and the
     custom-rule path no longer swallows its error by returning `ShowSubcommandHelp`. The
     argument handling moved into `newDeleteCustomRulesInput` /
     `newDeleteManagedRuleExclusionInput` so the CLI layer is testable at all — there was no
     harness for it before.*
  2. *Policy: `DeleteManagedRuleExclusion` had a hand-rolled resolver covering hashes and full
     ids but **no alias branch at all**; it now calls `GetWAFPolicyResourceID` like
     `AddManagedRuleExclusion:125` does, and receives a populated `ConfigPath`.*
  3. *`DeleteManagedRuleExclusionCLIInput` was a third instance of the S8/S16 shadowing family
     (duplicate `SubscriptionID` and `Debug` over an embedded `BaseCLIInput`); the duplicates are
     removed. A `Session` seam was added.*

  *Covered by `TestDeleteCustomRuleResolvesAlias`, `TestDeleteManagedRuleExclusionResolvesAlias`
  and `TestDeleteCommandsRejectUnknownPolicyName` in `policy/`, plus four builder tests in
  `cmd/commands/cmdDelete_test.go` asserting aliases and hashes pass through untouched and that
  `ConfigPath` is populated. The alias tests fail against the old resolver; the unknown-name test
  showed the old path surfacing `parameter resourceGroupName cannot be empty` from the Azure SDK
  instead of a clear error.*

  *Trade-off: a bad policy name now fails after session setup rather than instantly, and no
  longer prints the subcommand help. That is what makes aliases work, and it matches
  `add exclusion`.*

- [x] **S5. "Conditions per custom rule: 10" is never checked.** `README.md` Limits table.
  `MaxConditionsPerCustomRule` (`policy/policy.go:75`) has zero references repo-wide.
  *Doc now marks it as an Azure limit azwaf does not enforce. Adding enforcement remains open.*

- [x] **S6. `CLAUDE.md`'s priority ordering is not enforced anywhere.** Duplicate of **A1** from
  the other axis — both axes found it independently.

- [x] **S7. `--quiet` is honoured by `backup` only.** `README.md` lists it under "Global flags …
  accepted by every command". It is registered globally (`cmd/azwaf/main.go:80`) and so is
  *accepted* everywhere, but only `policy/backup.go:202,206` consume it. Every other command
  prints regardless. *Doc now states the limitation. Threading it through the remaining
  commands remains open.*

### (c) Implemented but wrong

- [x] **S8. `copy --dry-run` pushes anyway; `copy` with hashes always fails.** `CopyRulesInput`
  (`policy/copy.go:18-31`) embeds `BaseCLIInput` *and* redeclares `SubscriptionID`, `DryRun`,
  `Debug`, `Quiet`, `AppVersion`. The outer fields shadow the embedded ones.
  `cmd/commands/cmdCopy.go:26-34` populates only the embedded `BaseCLIInput`, so `i.DryRun`
  (`policy/copy.go:139`) and `i.SubscriptionID` (`policy/copy.go:46,55`) are always zero.
  `--dry-run` therefore pushes to Azure, contradicting `README.md` ("Generate the policy but do
  not push"), and hash resolution fails, contradicting "Hashes can be used". Compounding it,
  `CopyRulesInput.Validate()` (`policy/copy.go:206`) is never called, unlike `backup`
  (`policy/backup.go:67`) and `restore` (`policy/restore.go:119`).
  **Highest-severity finding: a documented safety flag silently does nothing.**
  *Fixed the same way as **S16**: the five duplicate fields are gone and only the embedded
  `BaseCLIInput` remains (`policy/copy.go:17-32`), so `i.DryRun`, `i.SubscriptionID`, `i.Debug`
  and `i.AppVersion` now read the values `cmd/commands/cmdCopy.go:26-34` sets. No changes were
  needed at that call site. `i.ConfigPath` was never shadowed and already worked. A `Session`
  seam was added, and the four existing `Validate()` tests in `policy/copy_test.go` were moved
  onto the embedded field. Covered by `TestCopyRulesDryRunPushesNothing` (nothing pushed, target
  keeps its own rule, no auto-backup written) and `TestCopyRulesAppliesAndUsesEmbeddedFields`
  (copy lands, pre-change backup captures the old target). Both fail against the old struct.*

  **`Validate()` is still not wired up, deliberately.** The review suggested calling it as
  `backup` and `restore` do, but it calls `ValidateResourceID(c.Source, false)`, which accepts
  hashes and full resource IDs while **rejecting aliases** — anything without a `/` fails at
  `policy/validation.go:165`. Calling it as-is would reproduce **S4** on `copy`, breaking a
  documented way of naming a policy. Wiring it up needs alias-aware validation, or the check
  moved after `GetWAFPolicyResourceID` has resolved the name. Left open on purpose.
  The `CustomRulesOnly && ManagedRulesOnly` conflict it also guards is still caught, just later,
  by `copyPolicyRules` (`policy/copy.go:181`).

- [x] **S9. Exclusion limit checked at wrong granularity.** `README.md` — "Exclusions per
  **scope** | 100 (warns at 95)". `policy/output.go:609-614` compares
  `stats[x].TotalExclusions`, which is the *sum* across all three scopes
  (`policy/policy_managed.go:1023`). The check is also display-only — it fires while rendering
  `show policy --stats` and `add exclusion` never consults it.

  *Fixed, both halves.*

  *Granularity: `policyExclusionScopes` walks the policy and returns one entry per rule set, per
  rule group override and per rule override, each with its own count, and both the warning and
  the new check read those rather than a sum. The old arithmetic was wrong in both directions —
  40 exclusions in each of three scopes totals 120 and was reported as a breach though no scope
  was close, while a genuine breach in one scope alongside empty others could stay under the
  combined threshold. The messages now name the offending scope instead of saying "policy".
  The at-limit message also printed `maxExclusionLimit/maxExclusionLimit`, so it read "100/100"
  regardless of the real count; it reports the count now.*

  *Placement: the check is no longer display-only. `validatePolicyLimits` (`policy.go`) rejects
  an over-limit scope before pushing, alongside the custom-rule count from S10, so `copy`,
  `restore` and `add exclusion` all fail with a clear error and `--dry-run` reports it.
  `show policy --stats` keeps its advisory warning from 95.*

  *`warnOnExclusionLimits` was split into a pure `exclusionLimitWarnings` returning the messages
  and a thin printer. The warnings go through gookit/color, which caches its writer at package
  init, so swapping `os.Stdout` does not capture them — the split makes the logic testable
  without depending on that.*

  *Covered by six tests in `policy/exclusionlimits_test.go`, including the 40/40/40 false alarm,
  a breach at each of the three scopes individually, the boundary at exactly 100, and enforcement
  on the push path. Restoring the summed behaviour fails four of them. `README.md`'s Limits table
  now records the exclusion limit as enforced.*

- [x] **S10. The 90-custom-rule limit isn't enforced on documented paths.** `README.md` Limits
  table. Checked only at `policy/custom_rules.go:428` and `:713`, both inside the IP-nets
  pipeline that has no CLI entry point. `copy` (`policy/copy.go:190,199`) and
  `restore --custom-rules` replace `CustomRules` wholesale with no count check, so either can
  push a policy Azure will reject.

  *Fixed with a single `validatePolicyLimits` called from two choke points rather than patched
  into each command. All five CLI mutation paths — `copy`, `restore`, both `delete` subcommands
  and `add exclusion` — funnel through `ProcessPolicyChanges`, so the check sits there, ahead of
  the fetch, diff, dry-run return and auto-backup: an over-limit policy now fails before any of
  that work, and `--dry-run` reports it instead of claiming success. `PushPolicy` carries the
  same check as a backstop for direct callers, so no path can push an over-limit policy. The
  pre-existing IP-nets checks at `custom_rules.go:428,713` are left as they are.*

  *Covered by `TestCopyRulesRejectsOverLimitCustomRules` (which also asserts no auto-backup was
  written, proving it failed early), `TestProcessPolicyChangesDryRunStillReportsOverLimit`,
  `TestPushPolicyRejectsOverLimitCustomRules`, `TestProcessPolicyChangesAllowsExactlyTheLimit`
  (90 is allowed — guards the off-by-one) and `TestValidatePolicyLimitsToleratesEmptyPolicy`.
  Three fail with the guards removed. `README.md`'s Limits table now records the rule count as
  enforced; the other three limits are still not, and the note says so.*

  *Noted, not fixed: `PushPolicy` (`policy/data.go:94`) dereferences `*i.Policy.Name` in a debug
  log without a nil check, so a policy with no name panics there. Same class as the
  `appendCustomRuleRows` derefs recorded under A5.*

- [x] **S11. Misleading `show policy` validation message.** `policy/validation.go:70` errors
  when `Custom && Managed && !Stats` — i.e. when *both* are set — but the message reads "at
  least one of --custom, --managed and --stats is required", describing the opposite condition.

  *The condition is correct and was left alone: `OutputPolicy` (`policy/output.go:1147,1153`)
  uses `--custom-only` to suppress managed rulesets and `--managed-only` to suppress custom
  rules, so together they render nothing but metadata — unless `--stats` is asked for, which
  prints regardless. Only the message was wrong, and now names what is actually rejected and how
  to proceed. Rewriting the condition to match the old message would have broken the documented
  no-flags default, which shows the whole policy.*

  *Covered by `TestShowPolicyValidateRejectsCombinedOnlyFlags` (which also asserts the old "at
  least one" wording is gone) and `TestShowPolicyValidateAllowsEveryOtherCombination`, a table
  over the five permitted combinations.*

- [x] **S15. `delete custom-rule` never takes an auto-backup.** `README.md` — "Mutating commands
  also create an auto-backup … unless `--auto-backup=false` is set."
  `cmd/commands/cmdDelete.go:133` populates `BaseCLIInput.AutoBackup`, but
  `DeleteCustomRulesCLI` (`policy/delete_custom_rule.go:207-215`) builds its
  `ProcessPolicyChangesInput` without a `Backup` field, so it defaults to `false` and the
  `if input.Backup` guard at `policy/policy.go:710` never fires. Every other mutating path sets
  it (`add_exclusions.go:197`, `delete_managed_exclusion.go:536`, `copy.go:140`,
  `restore.go:240`, `appgw_restore.go:326`). A destructive command silently skips the safety
  snapshot the docs promise.
  *Fixed: `DeleteCustomRulesCLI` now forwards `Backup: cliInput.BaseCLIInput.AutoBackup`. A
  `Session` seam was added to `DeleteCustomRulesCLIInput` (matching `RestorePoliciesInput`) so
  the wiring is testable, covered by `TestDeleteCustomRuleAutoBackupWritesPreChangeState` and
  `TestDeleteCustomRuleWithoutAutoBackupWritesNothing`. Both fail without the one-line fix.
  The README note describing the gap has been reverted.*
  Now written as `cliInput.AutoBackup`, which resolves through the embedded struct after S16.

- [x] **S16. `delete custom-rule --dry-run` deletes for real.** Same struct-shadowing defect as
  **S8**, on a second command. `DeleteCustomRulesCLIInput` (`policy/policy.go:385-399`) declares
  `BaseCLIInput` as a *named field* rather than embedding it, and then redeclares
  `SubscriptionID`, `DryRun`, `ConfigPath` and `Debug` alongside it. `cmd/commands/cmdDelete.go:127-144`
  populates only the `BaseCLIInput` field, so every outer twin stays at its zero value, while
  `DeleteCustomRulesCLI` reads the outer ones:
  - `cliInput.DryRun` (`policy/delete_custom_rule.go:215`) is always `false` → the `if input.DryRun`
    early return in `ProcessPolicyChanges` (`policy/policy.go:704`) never fires and the deletion
    is pushed.
  - `cliInput.SubscriptionID` / `cliInput.ConfigPath` (`:165-167`) are always `""` → hash and
    alias resolution get no subscription and no config, the S4 failure mode.
  - `cliInput.Debug`, `cliInput.MaxRules`, `cliInput.RID` likewise always zero.

  Verified against the fakes: driving the input exactly as the CLI does, with
  `BaseCLIInput{DryRun: true}`, still records one push to Front Door. **A documented safety flag
  silently does nothing on a destructive command — same severity as S8.**
  *Fixed: the four duplicated fields are gone and `BaseCLIInput` is now embedded
  (`policy/policy.go:385-400`), so every `cliInput.DryRun` / `.SubscriptionID` / `.ConfigPath` /
  `.Debug` read resolves to the value the CLI actually set — no call-site changes were needed,
  since the `BaseCLIInput:` composite literal in `cmd/commands/cmdDelete.go:131` is valid for an
  embedded field too. Covered by `TestDeleteCustomRuleDryRunPushesNothing` (asserts nothing is
  pushed, the rule survives in the store, and no auto-backup is written) and
  `TestDeleteCustomRuleUsesEmbeddedSubscriptionID`. Both fail against the old struct.*

  **S8 was the same defect on `copy`** and has since been fixed the same way.

### (b) Undocumented / scope creep

- [x] **S12. Debug `fmt.Printf` on stdout in `copy`** — `policy/copy.go:192-195,198`. Same as
  **A4**, and fixed with it.

- [x] **S13. `c.Bool("debug")` is read in six commands** (e.g. `cmd/commands/cmdAdd.go:77`,
  `cmd/commands/cmdShow.go:80`) but no `debug` flag is registered in `cmd/azwaf/main.go:68-82`.
  It is always false.

  *Fixed by registering the flag rather than removing the field. The plumbing behind it works —
  `Debug` reaches `checkDebug` (`policy/delete_custom_rule.go:69`), which sets the logger to
  debug level — it was simply unreachable, so a global `--debug` is now declared in
  `cmd/azwaf/main.go` alongside `--quiet`. Deleting the field instead would have meant unpicking
  `Debug` from a dozen structs to remove a feature that already worked. It is documented in
  `README.md` as a shortcut for `AZWAF_LOG=debug`.*

  *Covered by `TestNewDeleteInputsPropagateDebug` in `cmd/commands`, and confirmed against the
  built binary, which now lists `--debug` under GLOBAL OPTIONS. Note it is a global flag, so it
  goes before the command name.*

- [x] **S14. Undocumented surface.**
  - `list policies --max` is an undocumented alias for `--top` (`cmd/commands/cmdList.go:38`).
    *Now documented.*
  - `show policy --rule-name` (`cmd/commands/cmdShow.go:26`) is marked `Hidden: true`, so its
    absence from the README is **correct** — no action needed.
  - **Global flags are positional.** `README.md` said the four global flags are "accepted by
    every command". They are registered on the app, not the commands (`cmd/azwaf/main.go:68-82`),
    so they parse only *before* the command name; `azwaf backup --subscription-id X` exits with
    `flag provided but not defined: -subscription-id` (verified against a built binary).
    *Now documented.*
  - **`-s` is shadowed on five commands.** The global `-s` (`--subscription-id`) is overridden
    by a command-local `-s` on `backup` (`--storage-account-id`), `restore` (`--show-diff`),
    `copy` (`--source`), `add exclusion` and `delete managed-rule-exclusion`
    (`--match-selector`). Normal urfave/cli precedence, but a footgun the README did not
    mention. *Now documented.*
  - **`delete managed-rule-exclusion` scope flags have no short aliases.** `README.md` called it
    a "mirror of `add exclusion` — same scope and match flags", but `cmd/commands/cmdDelete.go:32-43`
    registers `rule-set`/`rule-group`/`rule-id` without the `-r`/`-g`/`-i` aliases that
    `cmdAdd.go:35-46` gives them. The match flags do match. *Now documented.*
  - The exported IP-nets library API (`RemoveNets`, `GenCustomRulesFromIPNets`,
    `UpdatePolicyCustomRulesIPMatchPrefixes`) has no CLI entry point. Within it,
    `policy/custom_rules.go:257` sets `Output: input.Quiet` — inverted, since `Quiet` true
    should suppress output.

    *Fixed by deleting `Output` rather than inverting the assignment. It was declared on four
    structs (`ApplyRemoveNetsInput`, `DecorateExistingCustomRuleInput`,
    `UpdatePolicyCustomRulesIPMatchPrefixesInput`, `AddCustomRulesPrefixesInput`), assigned in
    exactly one place — backwards — and read nowhere in live code; its only reader is inside the
    since-deleted `policy/block.go`. All four structs already embed `BaseCLIInput`, which
    carries `Quiet`: the same information, correctly named and the right way round. So `Output`
    was redundant as well as inverted, and correcting the value would have left a dead field
    waiting to be miswired again. Four declarations, one assignment and nine test assignments
    removed; no `Output` reference remains in the package.*

    *No behavioural test accompanies this one, and none is possible: the field had no reader, so
    there is no behaviour to assert. The compiler and the existing suite are the verification —
    the package builds, `go vet` and the linter are clean, and every test still passes.*

---

## Tooling note: golangci-lint

Throughout this pass `make lint` crashed with
`panic: file requires newer Go version go1.26 (application built with go1.25)`, so **golangci-lint
was not running at all** and every finding here was reached by reading, `go build`, `go vet` and
tests. The cause was environmental, not a repo defect: a golangci-lint binary built with go1.25
could not type-check a local toolchain that had moved to go1.26.7. It resolved when a build made
with go1.26.7 became first on `PATH` (`v2.13.0`). Nothing in the repo needed changing.

The repo pinned nothing about the linter — the `lint` target was a bare
`golangci-lint run ./...`, so which binary ran depended entirely on the developer's `PATH`, and
three were installed here at different versions (v2.11.4, v2.12.2 and v2.13.0).

*Now pinned*: the `Makefile` defines `GOLANGCI_LINT_VERSION := v2.13.0` and invokes the linter as
`go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)`. That
ignores `PATH` entirely and builds the pinned version with the *local* Go toolchain, so the
linter's type-checker always matches the Go in use — which is what makes this class of failure
impossible rather than merely unlikely. Verified by putting the v2.11.4 binary first on `PATH`:
`make lint-version` still reports v2.13.0. A `lint-version` target was added to make that easy to
check.

`go run <pkg>@<version>` was chosen over a `go.mod` `tool` directive to keep golangci-lint's large
dependency tree out of this project's `go.mod`.

The formatters are pinned the same way — `GOIMPORTS_VERSION := v0.49.0` (a `golang.org/x/tools`
version) and `GOFUMPT_VERSION := v0.11.0` — since an unpinned `gofumpt` reformats the tree the
moment upstream changes a rule. The installed copies were well behind (x/tools v0.33.0, gofumpt
v0.8.0); both pinned versions were checked with `-l` before adopting and reformat nothing, so
`make fmt` is a verified no-op on the current tree. A `tool-versions` target reports all three.

While pinning, `go get -u golang.org/x/tools/cmd/cover` was dropped from `setup`: `go tool cover`
ships with the Go distribution and is what the `coverage` target already uses, so the line did
nothing except risk mutating `go.mod` — in module mode `go get` adds the fetched package as a
dependency.

With the linter working, the tree reports **0 issues**. One pre-existing finding surfaced and was
fixed: `QF1012` at `policy/output.go:310`, `WriteString(fmt.Sprintf(...))` rewritten as
`fmt.Fprintf(&transformsOutput, ...)`. It predates this pass and was untouched by it. That single
finding across the whole tree also confirms this pass introduced no lint issues of its own.
`make ci` (lint + tests) now passes end to end.

## Documentation fixes applied

Corrections made to `CLAUDE.md` and `README.md` in this pass. These bring the docs in line with
what the code actually does; they deliberately do **not** paper over code defects.

1. `CLAUDE.md` — priority ordering reworded from "Enforces ordering" to a documented convention
   that is currently unimplemented, with a pointer to the dormant constants (A1 / S6).
2. `CLAUDE.md` — "Important Limits" split into limits azwaf actually enforces vs. Azure limits
   that are documented only (S5, S10).
3. `CLAUDE.md` — file-responsibility descriptions corrected for `policy/output.go` and the
   duplicated config parsing in `session/config.go` (A2).
4. `CLAUDE.md` — `AZWAF_LOG` description aligned with the five levels the code actually parses.
5. `README.md` — Limits table annotated with what azwaf enforces vs. surfaces vs. neither
   (S5, S9, S10).
6. `README.md` — `--quiet` marked as currently honoured by `backup` only (S7).
7. `README.md` — `--max` documented as an alias for `--top` (S14).
8. `README.md` — global flags described as position-sensitive (must precede the command name),
   replacing the incorrect "accepted by every command" (S14).
9. `README.md` — added a warning that `-s` is shadowed on five commands (S14).
10. `README.md` — `delete managed-rule-exclusion` no longer described as a flag-for-flag mirror
    of `add exclusion`; the missing `-r`/`-g`/`-i` aliases are called out (S14).
The auto-backup note was briefly amended to exclude `delete custom-rule`; that amendment has
been reverted now the code is fixed (S15), so the README's original claim holds again.

### Deliberately not "fixed" in the docs

Every finding on both axes has now been addressed in code or documentation. All eleven
duplicated-code clusters are collapsed. What remains open under P4 is the dead code /
speculative generality and the primitive obsession / middle man / data clumps groups, which are
refactors rather than defects.

The duplication pass was framed as tidying and did not stay that way. Six of the eleven clusters
were concealing a real difference between their two halves: two nil panics in the ProcessScope
pair, two more in the session client getters along with a wire-behaviour divergence where two
clients silently used SDK defaults instead of the project's retry and telemetry options, a
swallowed diff failure in the display path, two nil panics in the IP-nets collectors, and a
missing size guard that let `rebuildIPMatchConditions` emit a match condition more than three
times Azure's per-condition limit without complaint. None of these were visible as duplication;
they were visible only once the two halves had to be written as one. Roughly 850 lines of tests
were added to code that had none, and every behaviour change above was confirmed against the old
code before it was made.
