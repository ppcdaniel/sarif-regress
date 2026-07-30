# Controlled mutation of ESLint producer output

This fixture starts from output produced by the MIT-licensed
[`@microsoft/eslint-formatter-sarif` 3.1.0](https://github.com/microsoft/sarif-js-sdk/tree/main/packages/eslint-formatter-sarif)
running the MIT-licensed ESLint 8.57.1. The formatter's repository identifies
the package as an ESLint-to-SARIF formatter, and its
[`LICENSE`](https://github.com/microsoft/sarif-js-sdk/blob/main/LICENSE)
permits redistribution. ESLint's corresponding
[`LICENSE`](https://github.com/eslint/eslint/blob/v8.57.1/LICENSE)
is also MIT.

The output was captured on 2026-07-30 with Node.js 24.14.0. Equivalent
generation commands, run once for each source snapshot, are:

```bash
npm install --no-save eslint@8.57.1 \
  @microsoft/eslint-formatter-sarif@3.1.0
./node_modules/.bin/eslint example.js \
  --no-eslintrc \
  --env es6 \
  --rule 'eqeqeq:warn' \
  --rule 'no-eval:error' \
  --format ./node_modules/@microsoft/eslint-formatter-sarif \
  --output-file output.sarif
```

The candidate source adds exactly one leading comment line. After capture, the
fixture applies three documented, deterministic normalisations:

1. machine-specific absolute `file:` URIs become `src/example.js`;
2. the redundant artifact table/index emitted alongside each URI is removed;
3. the exact reported source line is copied into `region.snippet.text` so the
   public fixture is self-contained and does not depend on a checkout path.

Tool identity, rules, levels, messages, and reported coordinates otherwise
remain the formatter output. The two alerts must retain identity and classify
as moved. The missing GitHub-recommended line hashes are intentionally retained
and asserted as exact compatibility diagnostics.
