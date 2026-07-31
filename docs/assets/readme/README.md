# README demo assets

The README demo uses the controlled real-producer fixture in
[`corpus/cases/eslint-real-mutation`](../../../corpus/cases/eslint-real-mutation).
Its SARIF was produced by ESLint 8.57.1 through
`@microsoft/eslint-formatter-sarif` 3.1.0; the fixture notes record the source,
licensing, and deterministic normalisations.

`capture-demo.sh` runs a real SarifRegress executable against that fixture. It
asserts the exact comparison summary, renders the terminal GIF from a `jq`
projection of the generated stable JSON, takes an unmodified headless-browser
screenshot of the generated static HTML report, and crops the first finding card
from a second browser capture.

From a Linux checkout with Python 3.10+, `jq`, Chrome or Chromium, and
DejaVu Sans Mono installed:

```bash
python3 -m pip install \
  --requirement ./docs/assets/readme/requirements.txt
./scripts/package.sh
./docs/assets/readme/capture-demo.sh \
  ./artifacts/release/sarif-regress-linux-x64 \
  ./artifacts/readme-demo
```

The script writes generated reports and provenance checksums beneath
`artifacts/readme-demo/`; that destination must not already exist. Of the
generated outputs, only the reviewed GIF and PNG files are committed here.
The committed assets were generated with Pillow 11.3.0 and DejaVu Sans Mono.

## Committed-asset provenance

The committed bytes came from hosted capture
[run 30624256094](https://github.com/ppcdaniel/sarif-regress/actions/runs/30624256094)
at branch head `ad5c4d93310b098171a96364e79e5d7877106c50`. The job built the pinned
Release package before running the fixture and used Google Chrome
150.0.7871.128. The uploaded artifact has digest
`sha256:87b2ece12cf2d51499f048458337ccf8fa409669668f6ca3a4baecd65d64c3f6`.

| File | SHA-256 |
|---|---|
| Stable JSON | `a27ec720c779e48d1bd63a1c05f80b483451ff352aa792d900d39bd52d7d8c4a` |
| Generated HTML | `7e427c2fc2c978730338b828c0d22126946ea4e6bf708be275e690f32840fc11` |
| Browser version record | `1cc8bcac4b0c2d54fa0c22857b9ca430b10d551e5719e0032b18f97b09ff9035` |
| Terminal GIF | `dae6b9537e6f155835a2d37b943f74ed1af8e8e9877239b12750b65d3a3bb7fc` |
| HTML summary screenshot | `11f76569aafcf32f98b3580a8b45970ee9be54ae7eba4efcd9570d792ce80a6c` |
| First-finding crop | `05c1a1b9430335f4c353ac5bdc9623f0e08e7c48d386e5f4bdcb2626402be113` |
