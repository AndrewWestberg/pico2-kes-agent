# Performance gate

Status: **BLOCKED / not activated**. No comparable baseline/build, supported controlled environment, measurement instrument approval or sensitivity demonstration has been established. No baseline/candidate timing samples were collected; no zero-time baseline, medians, regression verdict or SC-002 pass is invented.

The existing supporting command `cargo run --locked -p qualification -- load` passed for its [recorded development snapshot](../../f23486803f9d2c730a4c943d6c32cdead361bfe9-615982a894f261dd0055905c683597def2687cc72e35ba4f08ec60b51cce50b1/load/report.json):

| Host-model check | Executions | Elapsed seconds including command/test overhead | Result |
|---|---:|---:|---|
| 64-active/64-staged pool isolation and enrollment-65 rejection | 1 | 4.893796052 | Pass |
| Stalled/malformed client isolation | 1 | 0.212546412 | Pass |

These are model/client-isolation readings, not packaged TUI timings, hardware capacity/durability or node interoperability. The report's acceptance claim is confined to its own stated scope.

To activate the required gate, retain the maintainer-approved comparable baseline, build/tool/environment identities and thresholds; use supported hosts and the actual 64-active/64-staged device workload; demonstrate detection of the isolated two-second Overview slowdown; then perform the prescribed warmup and five alternating pairs, retaining every sample and noise-aware verdict. Do not use the current candidate as its own baseline or infer performance from the development terminal smokes.
