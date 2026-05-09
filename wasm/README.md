# @uruhalushia/rule-converter-wasm

WebAssembly bindings for browser usage. This package exposes payload-based conversion only; file and directory APIs stay in the CLI/N-API packages.

## Build

Install the wasm target and `wasm-pack` first:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
pnpm --dir wasm build
```

The build scripts pass `--no-opt` because current Rust emits bulk-memory instructions that older bundled `wasm-opt` builds may reject. Browser runtimes support these instructions.

For bundlers such as Vite/Webpack:

```bash
pnpm --dir wasm build:bundler
```

## Local Usage After Build

After running `pnpm --dir wasm build`, the browser-ready package is generated in `wasm/pkg`. The files in `pkg` are ignored by git and can be served directly during local development.

### Browser Without A Bundler

Create an HTML file outside `pkg`, then import the generated module by relative path:

```html
<!doctype html>
<meta charset="utf-8" />
<button id="convert">convert</button>
<script type="module">
  import init, { strToBuf } from './wasm/pkg/rule_converter_wasm.js'

  await init()

  document.querySelector('#convert').addEventListener('click', () => {
    const result = strToBuf(
      `payload:\n  - DOMAIN,example.com\n  - DOMAIN-SUFFIX,example.net\n`,
      {
        inputTarget: 'mihomo',
        inputFormat: 'yaml',
        inputBehavior: 'classical',
        outputTarget: 'mihomo',
        outputFormat: 'mrs',
        outputBehavior: 'domain',
      },
    )

    const bytes = result.outputs.domain
    console.log(result.info.domain.behavior, result.info.domain.format, result.info.domain.count, bytes)
  })
</script>
```

Serve the repository directory with any static server; opening the file directly with `file://` usually fails because WebAssembly modules are fetched asynchronously.

```bash
python -m http.server 5173
# open http://localhost:5173/your-test.html
```

### Bundler / Vite / Webpack

Build the bundler package first:

```bash
pnpm --dir wasm build:bundler
```

Then install the generated local package in your web app:

```bash
pnpm add file:/home/atri/git/xishang/rule-converter/wasm/pkg
```

Use it from app code:

```js
import init, { strToBuf } from '@uruhalushia/rule-converter-wasm'

await init()

const result = strToBuf(
  `payload:\n  - DOMAIN,example.com\n  - DOMAIN-SUFFIX,example.net\n`,
  {
    inputTarget: 'mihomo',
    inputFormat: 'yaml',
    inputBehavior: 'classical',
    outputTarget: 'mihomo',
    outputFormat: 'mrs',
    outputBehavior: 'domain',
  },
)

for (const [name, bytes] of Object.entries(result.outputs)) {
  console.log(name, result.info[name].behavior, result.info[name].format, result.info[name].count, bytes)
}
```

The returned `bytes` value is a `Uint8Array`, so it can be downloaded, uploaded, or stored in IndexedDB directly.

MMDB list APIs also accept uploaded file bytes:

```js
import init, { listAsnNumbers, listGeoipCountries, listGeoipDatCountries, listGeositeCodes } from '@uruhalushia/rule-converter-wasm'

await init()

const bytes = new Uint8Array(await file.arrayBuffer())
console.log(listGeoipCountries(bytes))
console.log(listAsnNumbers(bytes))
console.log(listGeoipDatCountries(geoipDatBytes))
console.log(listGeositeCodes(geositeDatBytes))
```

DB conversions use the same `bufToBuf` / `bufToStr` functions. For example:

```js
const db = new Uint8Array(await mmdbFile.arrayBuffer())
const cn = bufToStr(db, {
  inputTarget: 'geoip',
  inputFormat: 'mmdb',
  outputTarget: 'general',
  outputFormat: 'ipset',
  countries: ['cn'],
  split: false,
})
const dat = bufToBuf(db, {
  inputTarget: 'geoip',
  inputFormat: 'mmdb',
  outputTarget: 'geoip',
  outputFormat: 'dat',
})
const geositeRules = bufToStr(geositeDatBytes, {
  inputTarget: 'geosite',
  inputFormat: 'dat',
  outputTarget: 'general',
  outputFormat: 'ruleset',
  codes: ['cn'],
  split: false,
})
```

Options use the same names as the N-API package:

```ts
type RuleTarget = 'mihomo' | 'general' | 'egern' | 'sing-box'
type InputFormat = 'yaml' | 'mrs' | 'text' | 'json' | 'srs' | 'domainset' | 'ruleset' | 'ipset' | 'mmdb' | 'sing-db' | 'metadb' | 'dat'
type OutputFormat = 'mrs' | 'text' | 'yaml' | 'json' | 'srs' | 'domainset' | 'ruleset' | 'ipset' | 'mmdb' | 'sing-db' | 'metadb' | 'dat'
type InputBehavior = 'auto' | 'domain' | 'ip' | 'classical'
type OutputBehavior = 'domain' | 'ip' | 'classical'
```

Defaults are `outputTarget: 'mihomo'`, `outputFormat: 'mrs'`, and `outputBehavior: 'domain'`.
