# README demo assets

The README demo uses the controlled real-producer fixture in
[`corpus/cases/eslint-real-mutation`](../../../corpus/cases/eslint-real-mutation).
Its SARIF was produced by ESLint 8.57.1 through
`@microsoft/eslint-formatter-sarif` 3.1.0; the fixture notes record the source,
licensing, and deterministic normalisations.

`capture-demo.sh` runs a real SarifRegress executable against that fixture. It
asserts the exact comparison summary, renders the terminal GIF from a `jq`
projection of the generated stable JSON, and takes an unmodified headless-browser
screenshot of the generated static HTML report.

From a Linux checkout with Python 3, `jq`, and Chrome or Chromium installed:

```bash
python3 -m pip install \
  --requirement ./docs/assets/readme/requirements.txt
./scripts/package.sh
./docs/assets/readme/capture-demo.sh \
  ./artifacts/release/sarif-regress-linux-x64 \
  ./artifacts/readme-demo
```

The script writes generated reports and provenance checksums beneath
`artifacts/readme-demo/`; that destination must not already exist. Only the
reviewed GIF and PNG are committed here.
The committed assets were generated with Pillow 11.3.0 and DejaVu Sans Mono.

## Committed-asset provenance

The committed bytes came from hosted capture
[run 30622574705](https://github.com/ppcdaniel/sarif-regress/actions/runs/30622574705)
at branch head `7e47183705622328ed1c04467a9b47755f400f90`. The job built the pinned
Release package before running the fixture.

| File | SHA-256 |
|---|---|
| Stable JSON | `a27ec720c779e48d1bd63a1c05f80b483451ff352aa792d900d39bd52d7d8c4a` |
| Generated HTML | `7e427c2fc2c978730338b828c0d22126946ea4e6bf708be275e690f32840fc11` |
| Terminal GIF | `43a475f7d4421057406d2ef9ad500bd5a7fa7b6416b3673d4d976b21a59dc1b4` |
| HTML summary screenshot | `11f76569aafcf32f98b3580a8b45970ee9be54ae7eba4efcd9570d792ce80a6c` |
