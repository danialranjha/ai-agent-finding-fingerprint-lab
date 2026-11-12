# AI security finding identity under edits

A contained identity-stability experiment: a harmless comment can change a line-based finding key, while a structural key stays stable. That stability also groups distinct supplied sites within one function and class.

This is an **independent implementation of a selected specification rule**, not Cisco Foundry code, a security scanner, a vulnerability reproduction or a live-model test. Python parses invented source strings and associates supplied finding metadata with local records. It never executes those source strings or decides whether they contain vulnerabilities.

## Hypothesis

A leading-comment edit moves the supplied finding statement from line 2 to line 5. A key containing the line number creates a second local record. A key using only normalized file path, qualified function name and supplied weakness class updates the existing record. Two distinct supplied sites within the same function/class also share that structural key, exposing its granularity limit.

## Source

Cisco's [Foundry Constitution VIII](https://github.com/CiscoDevNet/foundry-security-spec/blob/c770bf7764265dda188d9a270b1105a4bb62759b/constitution.md) and [FR-090/091](https://github.com/CiscoDevNet/foundry-security-spec/blob/c770bf7764265dda188d9a270b1105a4bb62759b/spec.md#75-fingerprint) prescribe a deterministic fingerprint over normalized path, function/symbol and weakness class, excluding line numbers and snippets. [Source identities](source-manifest.json) pin the inspected files. The three-way comparison and fixtures here are our implementation choices.

The same source's FR-058 treats prior true-positive findings as investigation priors rather than conclusions. This experiment implements no verdict inheritance. Matching a record is separate from proving its current claim.

## Threat model and containment

The failure being tested is bookkeeping under edits, not an assumed successful attack. A scanning system may emit supplied records across different code revisions. Unstable keys can duplicate a record; coarse keys can associate distinct sites. The fixture builder, source parser, metadata and observer stay trusted.

- All source, paths, classes, markers and record IDs are invented. No credentials, proprietary source, real service addresses or exploit payloads.
- Source is parsed by Python AST, never imported or executed. `record` in the fixture is inert syntax, not a running function.
- The sink is an in-memory key-to-record index with CREATE/UPDATE events. UPDATE records an association; it does not update an issue tracker or revalidate a finding.
- No model, detector, network, shell command, provider, external action or persistent issue database is used by the experiment. The check runner starts only the local Python test process in owned temporary copies.

## Setup and reproduction

Python 3.10+ and the standard library. No packages, credentials or services needed. Run from the checkout:

```sh
python3 -B -m unittest -v
python3 -B experiment.py
python3 -B run_checks.py
```

The experiment writes [artifacts/run.json](artifacts/run.json) and [evidence.md](evidence.md). The check runner writes [artifacts/checks.json](artifacts/checks.json). Outputs contain no timestamps, host paths or timings; reproduction compares their bytes. Run from a writable checkout; only these generated files are replaced.

## Results

Ten designed pairs × three methods = 30 paired comparisons. These are deterministic fixture observations, not measured attack, false-positive or duplicate rates in a population.

- **Line position:** path, qualified function, class and supplied statement line.
- **Function text:** path, qualified function, class and SHA-256 of the entire selected function text.
- **Structural:** path, qualified function and class.

In the leading-comment pair, Line position creates record-1 then record-2. Function text and Structural create record-1 then update record-1. A comment after the selected statement or harmless statement formatting keeps its line key but changes its function-text key. Structural remains equal for those edits.

Unchanged source and equivalent relative path spelling remain equal under all three methods. Renaming the function, moving the file or changing the supplied class changes all three keys.

In the two-site pair, the statement markers are at lines 2 and 3 of the same function. Line position creates two records; Function text and Structural each retain one. This is a **grouping collision caused by omitted site identity**, not a cryptographic hash collision. The changed-body pair also retains its Structural key; no conclusion about vulnerability presence or repair follows.

Twelve focused tests pass. Temporarily adding line position to the structural key causes four assertion failures; dropping the class causes five. Both mutations run the same 12 tests, with zero setup errors or skips. [Full equality matrix, exact source pair and tuples](evidence.md).

## Technical walkthrough

For each pair, both records include inert source text, relative path, qualified symbol, supplied weakness class and statement marker. The parser locates exactly one matching function and marker. It records statement and function lines. The function-text method includes the full function source range; comments outside that range do not change it. Decorators and module-level context are outside this selected range.

Path normalization is lexical POSIX normalization, not filesystem resolution: `./src/tmp/../notes.py` becomes `src/notes.py`. Absolute paths, escapes, backslashes, empty paths and NULs are rejected. Classes and qualified symbols are exact strings. The selected parser supports direct module/class/function definitions, including qualified nested names; it does not index conditional definitions or resolve aliases. Duplicate qualified functions and absent/ambiguous sites raise errors. It is not a general Python language server.

Keys are serialized as canonical JSON arrays and hashed with SHA-256. Exact component arrays are retained alongside digests, so the reader can inspect what was included and omitted. Site marker, source revision and timestamps are not part of Structural. Each method starts a fresh local index for each pair, records the first event, then associates the second key. The hand-authored expected equality matrix is separate from key construction.

## Limits and engineering consequence

The classes and site labels are supplied, not discovered. This experiment does not assess vulnerability correctness, completeness, false-positive reduction, exploitability, scan speed, issue-tracker behavior, production symbol resolution or concurrency. It does not establish a universal definition of the same finding.

Path and symbol changes intentionally break the structural key. Two same-class sites within one function intentionally share it. If a product needs one issue per site, it needs an additional identity design and its own stability tests. A key stable under body edits cannot by itself authorize reuse of a previous security verdict.

Separate issue association from current evidence. Test harmless line shifts and same-function multiple-site cases before deciding how a scanner should deduplicate reports, and recheck the evidence supporting any current vulnerability claim.
