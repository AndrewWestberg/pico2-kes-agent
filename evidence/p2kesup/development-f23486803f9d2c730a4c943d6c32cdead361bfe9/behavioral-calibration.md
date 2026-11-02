# Behavioral calibration — partial development evidence

Status: **BLOCKED for complete T067 calibration**. The approved Rust unit-path demonstration was executed; packaged Q3 and applicable Python-runner defect detection were not.

The T001-approved exact command ran in a separate source/build copy at `/tmp/p2kesup-stale-calibration-y67p4pu1`, using Rust/Cargo 1.99.1 and the same locked inputs:

```sh
cargo test --locked --lib manager::observe::tests::stale_after_observation_failure -- --exact
```

Only the disposable copy's `src/manager/observe.rs`, `Track::fail`, was changed: when a last successful observation exists, return `ObservationState::Fresh` instead of `ObservationState::Stale`. Tests and expected values were unchanged. The candidate source was never modified with this defect.

| Build | Selected tests executed | Result | Wall seconds including build |
|---|---:|---|---:|
| Original | 1 | Pass | 10.97 |
| Deliberately defective | 1 | Expected assertion failure: left Fresh, right Stale, observe.rs:1146 | 5.29 |
| Restored | 1 | Pass | 5.22 |

Other workspace library targets selected zero tests; they are not counted as detections. All runs were within the approved 30-minute limits. This detected the intended behavioral defect, not a build error or unrelated failure.

| Identity | Original | Defective | Restored |
|---|---|---|---|
| observe.rs SHA-256 | `0c0ef43811955fea8418e931d62b65bc82f0de4f880db9dda001e0571735552a` | `1ed9f5787622fa5f278f2a3673ea8d71c899f9a59899e3850d2d99cadb104081` | `0c0ef43811955fea8418e931d62b65bc82f0de4f880db9dda001e0571735552a` |
| Isolated host-library test binary SHA-256 | `bdec8252926c4aae6eb7d1006ec8354e9a1c0005f1b11d660b4050876f0e83f4` | `cb3ff8406814175ae9e5019bd4d6f69c141a70e86d3755df2413785c9fd8dadb` | `bdec8252926c4aae6eb7d1006ec8354e9a1c0005f1b11d660b4050876f0e83f4` |

The candidate observe.rs hash before and after equalled the original/restored hash. The isolated source/build copy was removed. No defective binary was installed, published or used for qualification.

Remaining requirements: execute the original/defective/restored packaged Q3 observation on the approved supported disposable setup, preserving last-success evidence and detecting falsely fresh status within the contract. No applicable Python-runner known-defect report was established; its separate single-defect approval/demonstration is still required. The 84 passing Python examples and invalid-input refusals alone are not calibration. This unit-only Ubuntu 26.04 result does not activate the complete behavioral or performance gate.
