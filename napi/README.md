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
import {
  fileToBuf,
  listAsnNumbers,
  listGeoipCountries,
  listGeoipDatCountries,
  listGeositeCodes,
  strToBuf,
  strToStr,
} from '@uruhalushia/rule-converter-napi'

const payload = `
payload:
  - DOMAIN,example.com
  - DOMAIN-SUFFIX,example.net
  - IP-CIDR,192.168.1.0/24,no-resolve
`

const mrs = strToBuf(payload, {
  inputTarget: 'mihomo',
  inputFormat: 'yaml',
  inputBehavior: 'classical',
  outputTarget: 'mihomo',
  outputFormat: 'mrs',
  outputBehavior: 'domain',
})

writeFileSync('domain.mrs', mrs.outputs.domain)

const text = strToStr(payload, {
  inputTarget: 'mihomo',
  inputFormat: 'yaml',
  inputBehavior: 'classical',
  outputTarget: 'general',
  outputFormat: 'ruleset',
  outputBehavior: 'classical',
})

console.log(text.outputs.classical)

const srs = fileToBuf('rules.yaml', {
  outputTarget: 'sing-box',
  outputFormat: 'srs',
  outputBehavior: 'classical',
})

writeFileSync('classical.srs', srs.outputs.classical)

const geoip = fileToBuf('country.mmdb', {
  inputTarget: 'geoip',
  outputTarget: 'general',
  outputFormat: 'ipset',
  countries: ['cn'],
})

writeFileSync('cn.list', geoip.outputs.cn)

const singDb = fileToBuf('country.mmdb', {
  inputTarget: 'geoip',
  outputTarget: 'geoip',
  outputFormat: 'sing-db',
})

writeFileSync('country.sing.db', singDb.outputs.db)

console.log(listGeoipCountries('country.mmdb'))
console.log(listGeoipDatCountries('geoip.dat'))
console.log(listGeositeCodes('geosite.dat'))
console.log(listAsnNumbers('GeoLite2-ASN.mmdb'))
```

`outputs` is a name-keyed object. Rule output keys are usually behavior names such as `domain`, `ip`, or `classical`. DB export keys are country codes, ASN numbers, or `db` for a generated database.

## API

- `bufToBuf(input, options?)`: converts a `Uint8Array` payload and returns byte outputs.
- `strToBuf(input, options?)`: converts a string payload and returns byte outputs.
- `fileToBuf(input, options?)`: converts one input file path and returns byte outputs.
- `bufToStr(input, options?)`: converts a `Uint8Array` payload and returns UTF-8 text outputs.
- `strToStr(input, options?)`: converts a string payload and returns UTF-8 text outputs.
- `fileToStr(input, options?)`: converts one input file path and returns UTF-8 text outputs.
- `listGeoipCountries(input)`: reads a GeoIP MMDB file path and returns sorted country codes.
- `listGeoipCountriesFromBuffer(input)`: reads GeoIP MMDB bytes and returns sorted country codes.
- `listGeoipDatCountries(input)` / `listGeoipDatCountriesFromBuffer(input)`: reads V2Ray `geoip.dat` and returns sorted country codes.
- `listGeositeCodes(input)` / `listGeositeCodesFromBuffer(input)`: reads V2Ray `geosite.dat` and returns sorted site codes.
- `listAsnNumbers(input)`: reads an ASN MMDB file path and returns sorted ASN numbers.
- `listAsnNumbersFromBuffer(input)`: reads ASN MMDB bytes and returns sorted ASN numbers.

```ts
interface AnyConvertOptions {
  inputTarget?: 'mihomo' | 'general' | 'egern' | 'sing-box' | 'geoip' | 'geosite' | 'asn'
  inputFormat?: 'yaml' | 'mrs' | 'text' | 'json' | 'srs' | 'domainset' | 'ruleset' | 'ipset' | 'mmdb' | 'sing-db' | 'metadb' | 'dat'
  inputBehavior?: 'auto' | 'domain' | 'ip' | 'classical'
  outputTarget?: 'mihomo' | 'general' | 'egern' | 'sing-box' | 'geoip' | 'geosite' | 'asn'
  outputFormat?: 'mrs' | 'text' | 'yaml' | 'json' | 'srs' | 'domainset' | 'ruleset' | 'ipset' | 'mmdb' | 'sing-db' | 'metadb' | 'dat'
  outputBehavior?: 'auto' | 'domain' | 'ip' | 'classical'
  countries?: string[]
  codes?: string[]
  asns?: number[]
  split?: boolean
  country?: string
  code?: string
  asn?: number
}

interface AnyBufferResult {
  kind: 'rules' | 'db'
  outputs: Record<string, Uint8Array>
  info: Record<string, AnyOutputInfo>
  skipped: SkippedRule[]
}

interface AnyStringResult {
  kind: 'rules' | 'db'
  outputs: Record<string, string>
  info: Record<string, AnyOutputInfo>
  skipped: SkippedRule[]
}
```

Defaults:

- `inputTarget`: auto-detected rule input unless set to `geoip`, `geosite`, or `asn`
- `inputFormat`: auto-detected
- `inputBehavior`: `auto`
- `outputTarget`: `mihomo` for rule input, `general` for DB-to-rules export, or the same DB target for DB conversion
- `outputFormat`: `mrs` for rule input, `ipset` for DB-to-rules export, or `mmdb` for DB conversion
- `outputBehavior`: selected from the target/format default
- `split`: `true` for DB-to-rules export

DB conversions use the same functions as rule conversions:

- `inputTarget: 'geoip'`, `outputTarget: 'general' | 'mihomo' | 'egern' | 'sing-box'` exports GeoIP contents as rule sets.
- `inputTarget: 'asn'`, `outputTarget: 'general' | 'mihomo' | 'egern' | 'sing-box'` exports ASN contents as rule sets.
- `inputTarget: 'geoip'`, `outputTarget: 'geoip'` converts GeoIP DB bytes between `mmdb`, `sing-db`, `metadb`, and V2Ray `dat`.
- `inputTarget: 'geosite'`, `outputTarget: 'general' | 'mihomo' | 'egern' | 'sing-box'` exports V2Ray `geosite.dat` as rule sets.
- `inputTarget: 'geosite'`, `outputTarget: 'geosite'` filters or normalizes V2Ray `geosite.dat`; geosite DB only supports `dat`.
- `inputTarget: 'asn'`, `outputTarget: 'asn'` normalizes ASN MMDB bytes. ASN DB output only supports `mmdb`.
- Rule input can build DB output with `outputTarget: 'geoip'` plus `country`, `outputTarget: 'geosite'` plus `code`, or `outputTarget: 'asn'` plus `asn`.

`mihomo + text/yaml + domain` uses mihomo/Clash domain wildcard syntax such as `+.example.com`; `general + domainset + domain` uses domain-set syntax where `.example.com` means the domain itself and all subdomains.

`no-resolve` is preserved only between mixed text, mihomo YAML, and Egern ruleset YAML. MRS, sing-box JSON/SRS, and domain-set output do not have a field for it.
