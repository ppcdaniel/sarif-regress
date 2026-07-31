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

From a Linux checkout with Pillow, `jq`, and Chrome or Chromium installed:

```bash
./scripts/package.sh
./docs/assets/readme/capture-demo.sh \
  ./artifacts/release/sarif-regress-linux-x64 \
  ./artifacts/readme-demo
```

The script writes generated reports and provenance checksums beneath
`artifacts/readme-demo/`. Only the reviewed GIF and PNG are committed here.
