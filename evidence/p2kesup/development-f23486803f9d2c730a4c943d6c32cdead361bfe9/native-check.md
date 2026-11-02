# Native compatibility follow-through

Status: **PASS for isolated pinned build plus existing node-service protocol scope**; the original configured runner failure is retained, not rewritten. No live-node or peer-accepted-block claim.

`cargo run --locked -p qualification -- native-regression` failed because `/home/westbam/haskell/cardano-node` was at `d248299eb7db5e448ce688bfda52b1ba86be4377`, not the inventory's `746f1b3cbdaada2c3ed2f702b0946643248dd30b`. The configured consensus checkout matched `6673fce255f12addb602b0ae2d0a20f51a2cd519`. Its 13 node-service protocol regressions passed in 1.999028189 seconds; see the [unaltered report](../../f23486803f9d2c730a4c943d6c32cdead361bfe9-bcc3fa4a4d1463368c41e596c3efe6f1c850359b5d86f87aa8c6bf748348b132/native/report.json).

The required node commit was available locally. A disposable shared clone at `/tmp/p2kesup-pinned-native-0607_db5/cardano-node` was checked out detached at the required commit, leaving the user's checkout and `qualification/native-sources.json` unchanged. The existing two-line `cabal.project.local` selected `cardano-crypto-praos` flag `-external-libsodium-vrf`. The first offline attempt lacked a cached source dependency; the existing 725 MiB `dist-newstyle/src` source cache was copied into this clone, without editing dependencies or fetching new versions.

Exact command in that clone:

```sh
cabal build --offline cardano-node:exe:cardano-node
```

Exit 0, 104.36 seconds. GHC 9.12.4, `-O1`; `cabal-install version 3.16.1.0 `. The build emitted upstream redundant-import warnings. The linked executable's actual `--version` exited 0 and reported:

```text
cardano-node 11.2.0.164 - linux-x86_64 - ghc-9.12
git rev 746f1b3cbdaada2c3ed2f702b0946643248dd30b
```

Executable SHA-256: `43b4e48aab23469c7ea759624e7079d15412a9e86aad9baf5580a8ad5676ddb2`. The isolated checkout/build was removed after recording identity. This supplemental result supplies the pinned build missing from the configured report, paired with its passing unchanged node-service regression run. There was no live node start, connection, supplied-leadership exercise or independent generation-time backup decoding. Hardware/decoder and other release gates remain blocked in [acceptance](acceptance.md).
