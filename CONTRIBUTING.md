# Contributing

## Probe contributions

Probes are YAML files in `src/rag_auditor/probes/`. Each probe needs:

- A unique `id` following the pattern `D{N}-{P|A|R}-{NNN}` (P=benign, A=adversarial, R=regression)
- `type`: `benign`, `adversarial`, or `regression`
- `visibility`: `public` (included in this repo) or `private` (for maintainer-only adversarial packs)
- `expected_behavior`: one of the values defined in that dimension's YAML
- A clear `description` explaining what the probe tests and why it matters

Framework mapping is required — each probe should reference which regulatory article or provision it tests.

## Code contributions

- Open an issue before starting significant work
- Match the existing code style (no comments unless the WHY is non-obvious)
- Deterministic scoring is preferred over LLM-as-judge where possible
- All new dimensions must have at least 6 probes (mix of benign, adversarial, regression)

## Bug bounty (probe bypasses)

If you find a way to make a clearly non-compliant RAG endpoint score above 0.80 on any dimension using the public probe set, please report it as a GitHub issue marked `[bypass]`. Confirmed bypasses will be fixed in the next minor release and credited in the changelog.
