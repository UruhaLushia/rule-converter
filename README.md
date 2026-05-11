# rule-converter

规则转换工具。输入默认自动识别，也可以显式指定 target、format、behavior；输出通过 target、format、behavior 明确指定。

## 支持范围

输入会按文件扩展名和内容自动识别：

- mihomo YAML：顶层 `payload` 或 `rules`。rule-provider 的 classical payload 不带策略；如果读到主配置 `rules` 这种带策略的路由规则，写出 classical ruleset 时会剥掉策略字段。
- mihomo MRS：`.mrs` 或二进制 payload
- sing-box source JSON：`.json`，顶层 `version` + `rules`
- sing-box SRS：`.srs` 或 `SRS` 二进制 payload
- Egern rule-set YAML：`domain_set`、`domain_suffix_set`、`ip_cidr_set` 等字段
- 通用 text/list：一行一条规则，文件扩展名建议使用 `.list`

输出目标：

- `mihomo`: mihomo 规则语义，支持 YAML payload、MRS 和 text rule-provider。
- `general`: 通用文本规则语义，支持 mixed ruleset 和 domain-set。
- `egern`: Egern rule-set YAML 语义。
- `sing-box`: sing-box rule-set 语义，支持 source JSON 和 SRS。

输出格式：

- `mihomo`: `mrs`、`text`、`yaml`
- `sing-box`: `srs`、`json`
- `egern`: `ruleset`
- `general`: `domainset`、`ruleset`、`ipset`

输出行为：

- `domain`: 按 domain 输出。`mihomo + text/yaml` 使用 mihomo/Clash domain 通配语法。
- `ip`: 按 IP CIDR 输出。
- `classical`: 输出为带明确规则类型、无策略字段的 classical/mixed ruleset，适用于 non-mihomo ruleset、mihomo YAML、sing-box JSON/SRS。

`general + domainset` 和 `general + ipset` 不使用 `output_behavior`，格式本身决定输出 domain 或 IP。non-mihomo ruleset 支持 `output_behavior`：`domain`/`ip` 只保留对应类型，`classical` 映射为目标平台的 mixed ruleset。mihomo MRS 只支持 `domain`、`ip`；未指定行为时会跟随明确的 domain/ip 输入，mixed/classical 输入需要显式指定 `domain` 或 `ip`。sing-box SRS 是独立格式，不复用 mihomo MRS 容器。

输入覆盖项：

- `input_target`: `mihomo`、`general`、`egern`、`sing-box`。
- `input_format`: `yaml`、`mrs`、`text`、`json`、`srs`。
- `input_behavior`: `auto`、`domain`、`ip`、`classical`。用于自动检测不可靠时强制解释输入。

## 构建

```bash
cargo build --release -p rule-converter
```

N-API 包在 `napi/` 下单独构建：

```bash
pnpm --dir napi install
pnpm --dir napi build
```

WASM 包在 `wasm/` 下单独构建，用于浏览器/Web：

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
pnpm --dir wasm build
```

`wasm-pack` uses `--no-opt` in this package because current Rust emits bulk-memory instructions that older bundled `wasm-opt` builds may reject.

## CLI 用法

CLI 使用子命令。`convert` 做转换：最后一个路径是输出，其余路径是输入。输入会自动检测，输出默认是 `mihomo + mrs`，也可以用 `--output-target`、`--output-format`、`--output-behavior` 指定。

```bash
target/release/rule-converter convert rules.yaml rules.mrs
```

轻量检测输入文件类型，输出 JSON：

```bash
target/release/rule-converter detect rules.yaml geosite.dat country.mmdb
```

指定输出目标、格式和行为：

```bash
target/release/rule-converter convert \
  --output-target general \
  --output-format ruleset \
  --output-behavior classical \
  rules.yaml dist/rules.list
```

多个输入会合并后转换。输入可以是文件、目录，或最终路径组件中的 `*` 通配符：

```bash
target/release/rule-converter convert '/path/to/rules/*' dist/ad.mrs
```

复杂转换使用配置文件，包括指定输入 target、format、behavior，多输出，GeoIP/ASN 导出、构建、过滤和 DB 直转：

```bash
target/release/rule-converter convert --config examples/config.yaml
```


匹配域名或 IP，输出 JSON 结果；输入可以是普通规则文件、MRS/SRS，也可以是带 `rules` 和 `rule-providers` 的 Mihomo 配置。Mihomo 配置会按规则顺序匹配 `RULE-SET` provider，CLI 支持 provider 的本地 `path`、`file://` 和 HTTP(S) `url`，HTTP provider 会下载到内存中临时匹配。

```bash
target/release/rule-converter match ads.example.com rules.list
target/release/rule-converter match 10.2.3.4 --input-behavior classical rules.list
target/release/rule-converter match github.com config.yaml
```

查看 MMDB 中可用的国家代码或 ASN：

```bash
target/release/rule-converter convert --list geoip country.mmdb
target/release/rule-converter convert --list asn GeoLite2-ASN.mmdb
```

通用 mixed text 是一行一条、带明确规则类型的 ruleset：

```text
DOMAIN,example.com
DOMAIN-SUFFIX,example.net
IP-CIDR,192.0.2.0/24,no-resolve
```

domain-set 每行是域名，`.example.com` 表示匹配自身和全部子域名。输入是纯域名列表时会自动按 domain-set 读取；输入是带 `DOMAIN,`、`IP-CIDR,` 等明确类型的文本时会自动按 mixed ruleset 读取。

mihomo domain text 使用 mihomo/Clash 的 domain 通配语法：

```text
.example.com
.example.net
.ads.example
```

其中 `+.example.com` 匹配自身和全部子域名，`.example.com` 只匹配子域名。它不同于 general domain-set 的 `.example.com` 语义。

Egern 的 `no_resolve: true` 是 ruleset 顶层字段。读取 Egern 时会映射为 mixed IP 规则的 `no-resolve`；从 mixed 规则写回 Egern 时，如果存在 IP `no-resolve`，会写出顶层 `no_resolve: true`。

`no-resolve` 只在 mixed text / mihomo YAML / Egern ruleset YAML 之间保留。输出 MRS、sing-box JSON/SRS 或 domain-set 时会丢失，因为这些格式没有对应字段。

sing-box 的 `domain_suffix` 使用自身语义：`example.com` 表示自身和全部子域名，`.example.com` 表示只匹配子域名。转换到 mihomo domain text 时会分别写成 `+.example.com` 和 `.example.com`。

## WASM 用法

浏览器中使用 payload API，不包含文件系统读写：

```js
import init, { strToBuf } from './pkg/rule_converter_wasm.js'

await init()

const result = strToBuf(`payload:
  - DOMAIN,example.com
`, {
  inputTarget: 'mihomo',
  inputFormat: 'yaml',
  inputBehavior: 'classical',
  outputTarget: 'mihomo',
  outputFormat: 'mrs',
  outputBehavior: 'domain',
})

const bytes = result.outputs.domain
console.log(result.info.domain.behavior, result.info.domain.format, result.info.domain.count, bytes)
```

返回值里的 `bytes` 是 `Uint8Array`，可直接用于下载、上传或写入 IndexedDB。

WASM 也支持直接查看 MMDB 内容列表，传入上传文件的 `Uint8Array`：

```js
import init, { listAsnNumbers, listGeoipCountries } from './pkg/rule_converter_wasm.js'

await init()

const bytes = new Uint8Array(await file.arrayBuffer())
console.log(listGeoipCountries(bytes))
console.log(listAsnNumbers(bytes))
```

本地编译后可以直接引用 `wasm/pkg`：

```bash
pnpm --dir wasm build
python -m http.server 5173
```

```html
<script type="module">
  import init, { strToBuf } from './wasm/pkg/rule_converter_wasm.js'
  await init()
  const result = strToBuf(`payload:
  - DOMAIN,example.com
`, {
    inputTarget: 'mihomo',
    inputFormat: 'yaml',
    inputBehavior: 'classical',
    outputTarget: 'mihomo',
    outputFormat: 'mrs',
    outputBehavior: 'domain',
  })
  console.log(result.outputs.domain)
</script>
```

在 Vite/Webpack 等项目里，先运行 `pnpm --dir wasm build:bundler`，再用 `pnpm add file:/home/atri/git/xishang/rule-converter/wasm/pkg` 安装本地包，并从 `@uruhalushia/rule-converter-wasm` 导入。

## 配置文件

CLI 支持 YAML、TOML、JSON 配置文件：

```bash
target/release/rule-converter convert --config examples/config.yaml
```

配置使用 `jobs` 数组。相对路径按配置文件所在目录解析。

字段：

- `input.path`: 单个输入路径。
- `input.inputs`: 多个输入项。每项可以直接写路径，也可以写 `{ path, target, format, behavior }`；数据库构建项使用 `{ country, path, target, format, behavior }` 或 `{ asn, path, target, format, behavior }`。
- `input.target`: 可选，规则输入使用 `mihomo`、`general`、`egern`、`sing-box`；数据库输入使用 `geoip`、`geosite` 或 `asn`。
- `input.format`: 可选，规则输入使用 `yaml`、`mrs`、`text`、`json`、`srs`；`domainset`、`ruleset`、`ipset` 作为输入格式时按 `text` 读取。数据库输入使用 `mmdb`、`sing-db`、`metadb`、`dat`、`sing-geosite`，其中 `geosite` 支持 `dat` 和 `sing-geosite`，`asn` 只支持 `mmdb`。
- `input.behavior`: 可选，`auto`、`domain`、`ip`、`classical`。

- `output`: 单个输出项。
- `outputs`: 多个输出项，每项字段与 `output` 相同，可以分别指定 `path` / `dir` / `target` / `format` / `behavior` / `country` / `asn`。同一个 job 不能同时写 `output` 和 `outputs`。
- `output.path`: 输出文件路径。
- `output.dir`: 数据库导出时按 `country` 或 `asn` 拆分文件的目录。
- `output.country`: GeoIP 数据库导出国家代码或列表，例如 `country: cn` 或 `country: [cn, us]`，省略时导出全部。
- `output.asn`: ASN 数据库导出 ASN 或列表，例如 `asn: 13335` 或 `asn: [13335, 15169]`，省略时导出全部。
- `output.target`: 规则输出使用 `mihomo`、`general`、`egern`、`sing-box`；数据库输出使用 `geoip`、`geosite` 或 `asn`。
- `output.format`: mihomo 使用 `mrs`、`text`、`yaml`；sing-box 使用 `srs`、`json`；egern 使用 `ruleset`；general 使用 `domainset`、`ruleset`、`ipset`；数据库使用 `mmdb`、`sing-db`、`metadb`、`dat`、`sing-geosite`，其中 `geosite` 支持 `dat` 和 `sing-geosite`，`asn` 只支持 `mmdb`。
- `output.behavior`: 可选，`auto`、`domain`、`ip`、`classical`。`domainset`/`ipset` 不使用该项；mihomo MRS 的 `auto` 会跟随明确的输入类型。
- `defaults`: 多任务配置的默认值。

GeoIP/Geosite/ASN 数据库任务支持导出、构建和数据库格式直转：

```yaml
jobs:
  - input:
      path: geoip.mmdb
      target: geoip
      format: mmdb
    outputs:
      - dir: dist/geoip
        target: general
        format: text
      - dir: dist/geoip-mrs
        target: mihomo
        format: mrs
        behavior: ip
      - path: dist/geoip.metadb
        target: geoip
        format: metadb
      - path: dist/geoip-cn.metadb
        target: geoip
        format: metadb
        country: cn

  - input:
      inputs:
        - country: cn
          path: dist/geoip/cn.list
          target: general
          format: ipset
        - country: us
          path: dist/geoip/us.list
          target: general
          format: ipset
    output:
      path: dist/geoip.mmdb
      target: geoip
      format: sing-db

  - input:
      path: asn.mmdb
      target: asn
      format: mmdb
    outputs:
      - dir: dist/asn
        target: general
        format: ipset
      - dir: dist/asn-mrs
        target: mihomo
        format: mrs
        behavior: ip
      - path: dist/asn-13335.mmdb
        target: asn
        format: mmdb
        asn: 13335

  - input:
      inputs:
        - asn: 13335
          path: dist/asn/13335.list
          target: general
          format: ipset
    output:
      path: dist/asn.mmdb
      target: asn
      format: mmdb
```

导出数据库时，如果使用 `output.dir` 会按 `country` 或 `asn` 拆分文件；省略 `output.country` / `output.asn` 时必须使用 `output.dir` 并导出全部条目。`output.path` 只用于显式指定 `country` / `asn` 后合并这些指定条目；单独输出可写 `country: cn` 或 `asn: 13335`。数据库导出可以接普通规则输出的 `target` / `format` / `behavior`，例如 `general ipset` 或 `mihomo mrs`。DB 直转也可以带 `country` / `asn`，用于重新生成只包含指定条目的数据库。构建 GeoIP 数据库时使用 `input.inputs` 中的 `country` 作为国家代码，可写出 `mmdb`、`sing-db`、`metadb` 或 `dat`。构建 Geosite 数据库时使用 `input.inputs` 中的 `code` 作为站点代码，可写出 `dat` 或 `sing-geosite`。构建 ASN 数据库时使用 `input.inputs` 中的 `asn`，只支持 `mmdb`。

示例配置见 `examples/`：

- `examples/config.yaml`
- `examples/config.toml`
- `examples/config.json`

## Classical 拆分

mihomo classical rule-provider 规则本身不带策略。显式使用 `domain` 或 `ip` 输出时，会只保留对应 MRS 可表示的规则；使用 `classical` 输出时，会写回不带策略的 text/YAML ruleset。如果输入是主配置 `rules:` 里的带策略路由规则，策略字段会被剥离：

- `DOMAIN`、`DOMAIN-SUFFIX` -> `domain`
- `IP-CIDR`、`IP-CIDR6` -> `ip`

不能安全转换的规则会进入 skipped，例如：

- `DOMAIN-KEYWORD`
- `DOMAIN-REGEX`
- `DOMAIN-WILDCARD`
- `GEOSITE`
- `GEOIP`
- `MATCH`

## 内存行为

文件路径输入会流式读取文本、mihomo YAML 和 Egern YAML。YAML 通过事件流解析，不会为了格式化 YAML 构建完整 YAML DOM。大文件转换时优先使用文件路径输入，避免 payload API 在调用方和 Rust 内部同时持有完整输入。

仍然不可避免存在和输出规则集规模相关的内存占用：domain 输出需要保留归一化后的唯一域名，ip 输出需要保留 CIDR 范围用于合并和编码，MRS 输入需要先解压再解析。

## 开发检查

```bash
cargo fmt --all --check
cargo test -p rule-converter
cargo check -p rule-converter-napi
```
