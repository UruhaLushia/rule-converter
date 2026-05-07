# @uruhalushia/rule-converter-napi

Node.js bindings for the Rust rule converter. Inputs are auto-detected from payload/file content by default, and can be overridden with input options when needed.

## Build

```bash
pnpm --dir napi install
pnpm --dir napi build
```

## Usage

```js
import { writeFileSync } from 'node:fs'
import { convertPayloadStringToMrs, convertFileToPath } from '@uruhalushia/rule-converter-napi'

const payload = `
payload:
  - DOMAIN,example.com
  - DOMAIN-SUFFIX,example.net
  - IP-CIDR,192.168.1.0/24,no-resolve
`

const result = convertPayloadStringToMrs(payload, {
  inputTarget: 'mihomo',
  inputFormat: 'yaml',
  inputBehavior: 'classical',
  outputTarget: 'mihomo',
  outputFormat: 'mrs',
  outputBehavior: 'domain',
})

for (const output of result.outputs) {
  writeFileSync(`${output.behavior}.mrs`, output.bytes)
}

const written = convertFileToPath('rules.yaml', 'dist/rules.list', {
  outputTarget: 'general',
  outputFormat: 'text',
  outputBehavior: 'classical',
})

console.log(written.outputs)
```

Multiple files can be merged by passing a path array, a directory path, or a final-component `*` wildcard:

```js
convertFileToPath(['/path/rules-a.yaml', '/path/rules-b.yaml'], 'dist/ad.mrs', {
  outputTarget: 'mihomo',
  outputFormat: 'mrs',
  outputBehavior: 'domain',
})
```

## API

- `convertPayloadToMrs(payload, options?)`: accepts `Uint8Array` and returns generated MRS files in memory.
- `convertPayloadStringToMrs(payload, options?)`: accepts a string and returns generated MRS files in memory.
- `convertFileToMrs(input, options?)`: reads one file, directory, wildcard, or path array and returns generated MRS files in memory.
- `convertFileToPath(input, output, options?)`: writes converted outputs to disk.

```ts
interface ConvertOptions {
  inputTarget?: 'mihomo' | 'general' | 'egern' | 'sing-box'
  inputFormat?: 'yaml' | 'mrs' | 'text' | 'json' | 'srs'
  inputBehavior?: 'auto' | 'domain' | 'ip' | 'classical'
  outputTarget?: 'mihomo' | 'general' | 'egern' | 'sing-box'
  outputFormat?: 'mrs' | 'text' | 'yaml' | 'json' | 'srs' | 'domainset' | 'ruleset' | 'ipset'
  outputBehavior?: 'domain' | 'ip' | 'classical'
}
```

Defaults:

- `inputTarget`: auto-detected
- `inputFormat`: auto-detected
- `inputBehavior`: `auto`
- `outputTarget`: `mihomo`
- `outputFormat`: `mrs`
- `outputBehavior`: `domain`

mihomo MRS output supports only `domain` and `ip`. sing-box JSON/SRS is available with `outputTarget: 'sing-box'` and `outputFormat: 'json' | 'srs'`.

`mihomo + text/yaml + domain` uses mihomo/Clash domain wildcard syntax such as `+.example.com`; `general + domainset + domain` uses domain-set syntax where `.example.com` means the domain itself and all subdomains.

`no-resolve` is preserved only between mixed text, mihomo YAML, and Egern ruleset YAML. MRS, sing-box JSON/SRS, and domain-set output do not have a field for it.
