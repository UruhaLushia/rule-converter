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

- `domain`: 按 domain 输出。`mihomo + text/yaml` 使用 mihomo/Clash domain 通配语法，`general + domainset` 使用 domain-set 语法。
- `ip`: 按 IP CIDR 输出。
- `classical`: 输出为带明确规则类型、无策略字段的 classical/mixed ruleset，适用于 general ruleset、mihomo YAML、Egern YAML、sing-box JSON/SRS。

mihomo MRS 只支持 `domain`、`ip` 输出行为，不支持 `classical`。sing-box SRS 是独立格式，不复用 mihomo MRS 容器。

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

默认输出是 `mihomo + mrs + domain`：

```bash
target/release/rule-converter rules.yaml rules.mrs
```

显式指定输出：

```bash
target/release/rule-converter \
  --output-target mihomo \
  --output-format mrs \
  --output-behavior domain \
  rules.yaml dist/rules.mrs
```

显式指定输入解释：

```bash
target/release/rule-converter \
  --input-target general \
  --input-format text \
  --input-behavior domain \
  --output-target general \
  --output-format domainset \
  --output-behavior domain \
  domains.list dist/domains.list
```

多个输入会合并后转换。输入可以是文件、目录，或最终路径组件中的 `*` 通配符：

```bash
target/release/rule-converter '/path/to/rules/*' dist/ad.mrs
```

输出为通用 mixed text：

```bash
target/release/rule-converter \
  --output-target general \
  --output-format ruleset \
  --output-behavior classical \
  rules.yaml dist/rules.list
```

通用 mixed text 是一行一条、带明确规则类型的 ruleset：

```text
DOMAIN,example.com
DOMAIN-SUFFIX,example.net
IP-CIDR,192.0.2.0/24,no-resolve
```

通用 domainset 使用 `output_behavior = domain`：

```bash
target/release/rule-converter \
  --output-target general \
  --output-format domainset \
  --output-behavior domain \
  domains.list dist/domains.list
```

domain-set 每行是域名，`.example.com` 表示匹配自身和全部子域名。输入是纯域名列表时会自动按 domain-set 读取；输入是带 `DOMAIN,`、`IP-CIDR,` 等明确类型的文本时会自动按 mixed ruleset 读取。

mihomo domain text 使用 mihomo/Clash 的 domain 通配语法：

```text
.example.com
.example.net
.ads.example
```

其中 `+.example.com` 匹配自身和全部子域名，`.example.com` 只匹配子域名。它不同于 general domain-set 的 `.example.com` 语义。

Egern rule-set YAML 输入或输出：

```bash
target/release/rule-converter \
  --output-target mihomo \
  --output-format mrs \
  --output-behavior domain \
  egern.yaml dist/rules.mrs
```

```bash
target/release/rule-converter \
  --output-target egern \
  --output-format ruleset \
  --output-behavior classical \
  rules.yaml dist/egern.yaml
```

Egern 的 `no_resolve: true` 是 ruleset 顶层字段。读取 Egern 时会映射为 mixed IP 规则的 `no-resolve`；从 mixed 规则写回 Egern 时，如果存在 IP `no-resolve`，会写出顶层 `no_resolve: true`。

`no-resolve` 只在 mixed text / mihomo YAML / Egern ruleset YAML 之间保留。输出 MRS、sing-box JSON/SRS 或 domain-set 时会丢失，因为这些格式没有对应字段。

sing-box JSON/SRS 输入或输出：

```bash
target/release/rule-converter \
  --input-target general \
  --input-format text \
  --input-behavior classical \
  --output-target sing-box \
  --output-format srs \
  --output-behavior classical \
  rules.list dist/rules.srs
```

sing-box 的 `domain_suffix` 使用自身语义：`example.com` 表示自身和全部子域名，`.example.com` 表示只匹配子域名。转换到 mihomo domain text 时会分别写成 `+.example.com` 和 `.example.com`。

## WASM 用法

浏览器中使用 payload API，不包含文件系统读写：

```js
import init, { convertPayloadString } from './pkg/rule_converter_wasm.js'

await init()

const result = convertPayloadString(`payload:
  - DOMAIN,example.com
`, {
  inputTarget: 'mihomo',
  inputFormat: 'yaml',
  inputBehavior: 'classical',
  outputTarget: 'mihomo',
  outputFormat: 'mrs',
  outputBehavior: 'domain',
})

const first = result.outputs[0]
console.log(first.behavior, first.format, first.count, first.bytes)
```

返回值里的 `bytes` 是 `Uint8Array`，可直接用于下载、上传或写入 IndexedDB。

本地编译后可以直接引用 `wasm/pkg`：

```bash
pnpm --dir wasm build
python -m http.server 5173
```

```html
<script type="module">
  import init, { convertPayloadString } from './wasm/pkg/rule_converter_wasm.js'
  await init()
  const result = convertPayloadString(`payload:
  - DOMAIN,example.com
`, {
    inputTarget: 'mihomo',
    inputFormat: 'yaml',
    inputBehavior: 'classical',
    outputTarget: 'mihomo',
    outputFormat: 'mrs',
    outputBehavior: 'domain',
  })
  console.log(result.outputs[0].bytes)
</script>
```

在 Vite/Webpack 等项目里，先运行 `pnpm --dir wasm build:bundler`，再用 `pnpm add file:/home/atri/git/xishang/rule-converter/wasm/pkg` 安装本地包，并从 `@uruhalushia/rule-converter-wasm` 导入。

## 配置文件

CLI 支持 YAML、TOML、JSON 配置文件：

```bash
target/release/rule-converter --config examples/config.yaml
```

配置可以写一个顶层任务，也可以写 `jobs` 数组。相对路径按配置文件所在目录解析。

字段：

- `input`: 输入路径，支持字符串或字符串数组。路径可以是文件、目录或最终路径组件中的 `*` 通配符。
- `output`: 输出路径。
- `input_target`: 可选，`mihomo`、`general`、`egern`、`sing-box`。
- `input_format`: 可选，`yaml`、`mrs`、`text`、`json`、`srs`。
- `input_behavior`: 可选，`auto`、`domain`、`ip`、`classical`。
- `output_target`: `mihomo`、`general`、`egern`、`sing-box`。
- `output_format`: mihomo 使用 `mrs`、`text`、`yaml`；sing-box 使用 `srs`、`json`；egern 使用 `ruleset`；general 使用 `domainset`、`ruleset`、`ipset`。
- `output_behavior`: `domain`、`ip`、`classical`。`classical` 用于带明确规则类型的 mixed/classical 输出。
- `defaults`: 多任务配置的默认值。

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
