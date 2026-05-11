<div align="center">
  <img src="assets/nyx-wordmark.svg" alt="nyx" height="110"/>

**本地优先的安全扫描器，自带浏览器 UI。在本地扫描代码仓库并在浏览器中分诊处理，无需云端、无需账号。**

[![crates.io](https://img.shields.io/crates/v/nyx-scanner.svg)](https://crates.io/crates/nyx-scanner)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange)](https://www.rust-lang.org)
[![CI](https://img.shields.io/github/actions/workflow/status/elicpeter/nyx/ci.yml?branch=master)](https://github.com/elicpeter/nyx/actions)
[![Docs](https://img.shields.io/badge/docs-elicpeter.github.io%2Fnyx-blue)](https://elicpeter.github.io/nyx/)

[English](./README.md) · 简体中文
</div>

<p align="center"><img src="assets/screenshots/demo.gif" alt="Nyx UI 演示：从空欢迎页开始扫描，查看含健康分的总览页，钻入一条 HIGH 级发现的流可视化，再到分诊流程" width="900"/></p>

---

## 本地扫描，本地浏览

Nyx 在你的代码仓库上运行跨语言污点分析，然后将结果通过绑定到 `127.0.0.1` 的 React UI 提供给你。你会得到一份带严重等级、证据、以及分步**流可视化**的发现列表，从源 → 净化器 → 汇逐步呈现数据流。分诊决策持久化在 `.nyx/triage.json` 中，与代码一同提交，团队共享同一份分诊状态。

```bash
cargo install nyx-scanner
nyx scan           # 运行分析器，把发现缓存到 .nyx/
nyx serve          # 在浏览器中打开 http://localhost:9700
```

一切都留在你本地：仅回环绑定、强制 host 头校验、所有变更操作均带 CSRF、无遥测、无登录。

<p align="center"><img src="assets/screenshots/overview.png" alt="一个小型 JS 应用的总览仪表盘：健康分 C 78，五项分量分解（严重度压力、置信度质量、趋势、分诊覆盖、回归抗性），3 条发现，OWASP A03 与 A02 类别，置信度分布与问题类别条形图，受影响最多的文件" width="900"/></p>

---

## UI 中包含什么

| 页面 | 显示内容 |
|---|---|
| **总览** | 仪表盘：按严重等级分类的发现计数、热点文件、引擎画像摘要 |
| **发现** | 可浏览列表，含严重度徽章、分诊状态、规则筛选、语言筛选 |
| **发现详情** | 流路径可视化，带编号步骤（源 → 净化器 → 汇）、代码片段、证据、跨文件标记、分诊下拉框 |
| **分诊** | 批量更新状态（open、investigating、fixed、false_positive、accepted_risk、suppressed），审计日志，JSON 导入/导出 |
| **资源管理器** | 文件树，含每个文件的符号列表与发现叠加层 |
| **扫描** | 历史记录、指标，对比两次扫描查看差异 |
| **规则** | 各语言的内置与自定义规则；可在 UI 中添加规则 |
| **配置** | 实时配置编辑器；无需重启即可重载 |


`nyx serve` 参数：`--port <N>`（默认 `9700`）、`--host <addr>`（仅回环：`127.0.0.1`、`localhost`、`::1`）、`--no-browser`。持久化设置见 `nyx.conf` 的 `[server]` 段，分页面 UI 介绍与安全模型详见 [Browser UI 指南](https://elicpeter.github.io/nyx/serve.html)。

---

## 用于 CI 的 CLI

同一个引擎可以无头运行用于 CI 流水线。SARIF 输出可直接上传到 GitHub Code Scanning。

<p align="center"><img src="assets/screenshots/cli-scan.gif" alt="nyx scan 终端输出：JS 与 Python 文件中的 HIGH 级污点发现及 source → sink 箭头" width="820"/></p>

```bash
# 在 medium 及以上等级让 CI 失败，并输出 SARIF
nyx scan --format sarif --fail-on MEDIUM > results.sarif

# 临时 JSON，无索引
nyx scan ./server --format json --index off

# 仅 AST 模式（最快；跳过 CFG + 污点）
nyx scan --mode ast

# 引擎深度快捷方式：fast | balanced（默认） | deep
# `deep` 增加 symex 与按需后向污点，精度更高，开销约 2-3 倍
nyx scan --engine-profile deep
```

正向跨文件污点在所有画像下都会运行。Symex 与按需后向遍历是可选项，可通过 `--engine-profile deep` 一次性开启，或单独开启（`--symex`、`--backwards-analysis`）。完整开关矩阵见 [CLI 参考](https://elicpeter.github.io/nyx/cli.html#engine-depth-profile)。

### GitHub Action

```yaml
- uses: elicpeter/nyx@v0.7.0
  with:
    format: sarif
    fail-on: MEDIUM
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: nyx-results.sarif
```

输入：`path`、`version`、`format`（`sarif`|`json`|`console`）、`fail-on`、`args`、`token`。输出：`finding-count`、`sarif-file`、`exit-code`、`nyx-version`。支持 Linux 与 macOS runner（x86_64、ARM64）。

---

## 安装

**Cargo（推荐）：**
```bash
cargo install nyx-scanner
```

**预编译二进制：** 从 [Releases](https://github.com/elicpeter/nyx/releases) 下载对应平台的归档包，对照 `SHA256SUMS`（以及随附的 `SHA256SUMS.asc` GPG 签名，如有提供）校验，解压并把 `nyx` 放到 `PATH` 中。

```bash
# 可选：校验校验文件的 GPG 签名（当 SHA256SUMS.asc 已发布时）
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
unzip nyx-x86_64-unknown-linux-gnu.zip && chmod +x nyx && sudo mv nyx /usr/local/bin/
```

**从源码编译：**
```bash
git clone https://github.com/elicpeter/nyx.git
cd nyx && cargo build --release
```

需要 stable Rust 1.88+。前端会在编译期被打包嵌入二进制中，因此 `nyx serve` 没有单独的安装步骤。

---

## 语言支持

全部 10 种语言都通过 tree-sitter 解析并跑完整流水线，但规则深度与引擎覆盖并不均衡。在 [`tests/benchmark/ground_truth.json`](tests/benchmark/ground_truth.json) 的 507 案例语料上，所有十种语言的基准 F1 均为 100%，因此 F1 已无法单独区分梯度。分级反映规则深度、门控汇覆盖、以及合成语料未充分覆盖的结构性惯用法：

| 梯度 | 语言 | F1 | 适合用作 CI 门禁吗？ |
|---|---|---|---|
| **稳定** | Python、JavaScript、TypeScript | 100% | 适合 |
| **Beta** | Java、PHP、Ruby、Rust、Go | 100% | 适合，需轻度 FP 分诊 |
| **预览** | C、C++ | 合成语料 100% | 不适合。已跟踪 STL 容器流、builder 链、内联类成员函数；尚未覆盖深度指针别名与函数指针。建议与 clang-tidy 或 Clang Static Analyzer 搭配使用 |

聚合规则级 F1：100.0%（P=1.000，R=1.000）。所有真实 CVE 用例均触发，语料无未关闭的 FP。各维度详情与已知盲区见 [语言成熟度页面](https://elicpeter.github.io/nyx/language-maturity.html)。

### 通过真实 CVE 验证

语料中还包含一小批从公开公告中提取的「漏洞 / 已修复」配对，因此基准下限不仅由合成的同形测例守护，还由对真实 bug 的回归保护守护。每个配对 Nyx 都在漏洞文件上触发、在已修复文件上零发现。

| CVE | 项目 | 语言 | 类别 |
|---|---|---|---|
| [CVE-2023-48022](https://nvd.nist.gov/vuln/detail/CVE-2023-48022) | Ray | Python | 命令注入 |
| [CVE-2017-18342](https://nvd.nist.gov/vuln/detail/CVE-2017-18342) | PyYAML | Python | 反序列化 |
| [CVE-2019-14939](https://nvd.nist.gov/vuln/detail/CVE-2019-14939) | mongo-express | JavaScript | 代码执行（`eval`） |
| [CVE-2023-22621](https://nvd.nist.gov/vuln/detail/CVE-2023-22621) | Strapi | JavaScript | 代码执行（SSTI） |
| [CVE-2025-64430](https://nvd.nist.gov/vuln/detail/CVE-2025-64430) | Parse Server | JavaScript | SSRF |
| [CVE-2023-26159](https://nvd.nist.gov/vuln/detail/CVE-2023-26159) | follow-redirects | TypeScript | SSRF |
| [GHSA-4x48-cgf9-q33f](https://github.com/advisories/GHSA-4x48-cgf9-q33f) | Novu | TypeScript | SSRF |
| [CVE-2026-25544](https://nvd.nist.gov/vuln/detail/CVE-2026-25544) | Payload CMS | TypeScript | SQL 注入 |
| [CVE-2022-30323](https://nvd.nist.gov/vuln/detail/CVE-2022-30323) | hashicorp/go-getter | Go | 命令注入 |
| [CVE-2024-31450](https://nvd.nist.gov/vuln/detail/CVE-2024-31450) | owncast | Go | 路径穿越 |
| [CVE-2023-3188](https://nvd.nist.gov/vuln/detail/CVE-2023-3188) | owncast | Go | SSRF |
| [CVE-2026-41422](https://github.com/daptin/daptin/security/advisories/GHSA-rw2c-8rfq-gwfv) | daptin | Go | SQL 注入 |
| [CVE-2015-7501](https://nvd.nist.gov/vuln/detail/CVE-2015-7501) | Apache Commons Collections | Java | 反序列化 |
| [CVE-2017-12629](https://nvd.nist.gov/vuln/detail/CVE-2017-12629) | Apache Solr | Java | 命令注入 |
| [CVE-2022-1471](https://nvd.nist.gov/vuln/detail/CVE-2022-1471) | SnakeYAML | Java | 反序列化 |
| [CVE-2022-42889](https://nvd.nist.gov/vuln/detail/CVE-2022-42889) | Apache Commons Text | Java | 代码执行 |
| [GHSA-h8cj-hpmg-636v](https://github.com/advisories/GHSA-h8cj-hpmg-636v) | Appsmith | Java | SQL 注入 |
| [CVE-2013-0156](https://nvd.nist.gov/vuln/detail/CVE-2013-0156) | Ruby on Rails | Ruby | 反序列化 |
| [CVE-2020-8130](https://nvd.nist.gov/vuln/detail/CVE-2020-8130) | Rake | Ruby | 命令注入 |
| [CVE-2021-21288](https://nvd.nist.gov/vuln/detail/CVE-2021-21288) | CarrierWave | Ruby | SSRF |
| [CVE-2023-38337](https://nvd.nist.gov/vuln/detail/CVE-2023-38337) | rswag-api | Ruby | 路径穿越 |
| [CVE-2017-9841](https://nvd.nist.gov/vuln/detail/CVE-2017-9841) | PHPUnit | PHP | 代码执行（`eval`） |
| [CVE-2018-15133](https://nvd.nist.gov/vuln/detail/CVE-2018-15133) | Laravel | PHP | 反序列化 |
| [CVE-2018-20997](https://nvd.nist.gov/vuln/detail/CVE-2018-20997) | tar-rs | Rust | 路径穿越 |
| [CVE-2022-36113](https://nvd.nist.gov/vuln/detail/CVE-2022-36113) | cargo | Rust | 路径穿越 |
| [CVE-2024-24576](https://nvd.nist.gov/vuln/detail/CVE-2024-24576) | Rust stdlib | Rust | 命令注入 |
| [CVE-2023-42456](https://rustsec.org/advisories/RUSTSEC-2023-0069.html) | sudo-rs | Rust | 路径穿越 |
| [CVE-2024-32884](https://rustsec.org/advisories/RUSTSEC-2024-0335.html) | gitoxide | Rust | 命令注入 |
| [CVE-2025-53549](https://rustsec.org/advisories/RUSTSEC-2025-0043.html) | matrix-rust-sdk | Rust | SQL 注入 |
| [CVE-2016-3714](https://nvd.nist.gov/vuln/detail/CVE-2016-3714) | ImageMagick (ImageTragick) | C | 命令注入 |
| [CVE-2019-18634](https://nvd.nist.gov/vuln/detail/CVE-2019-18634) | sudo (pwfeedback) | C | 内存安全 |
| [CVE-2019-13132](https://nvd.nist.gov/vuln/detail/CVE-2019-13132) | ZeroMQ libzmq | C++ | 内存安全 |
| [CVE-2022-1941](https://nvd.nist.gov/vuln/detail/CVE-2022-1941) | Protocol Buffers | C++ | 内存安全 |
| [CVE-2025-69662](https://nvd.nist.gov/vuln/detail/CVE-2025-69662) | geopandas | Python | SQL 注入 |
| [CVE-2026-33626](https://nvd.nist.gov/vuln/detail/CVE-2026-33626) | LMDeploy | Python | SSRF |

用例文件位于 [`tests/benchmark/cve_corpus/`](tests/benchmark/cve_corpus/)，并附上游归属头注释。

---

## 工作原理

对文件系统进行两遍扫描，可选用 SQLite 索引跳过未变更文件：

1. **Pass 1**：用 tree-sitter 解析每个文件，构建过程内 CFG（petgraph），下降到剪枝后的 SSA（在支配边界上做 Cytron phi 插入），并导出每函数摘要（source/sanitizer/sink 能力位、污点变换、指向集、被调集合）。
2. **摘要合并**：将每文件摘要并集合并为 `GlobalSummaries` 映射。
3. **Pass 2**：在跨文件上下文与有限上下文敏感（文件内被调用 k=1 内联，SCC 不动点上限 64 次迭代，超过内联体大小阈值的被调用走摘要回退）下重新分析每个文件。正向数据流工作表通过 SSA 格传播污点，保证收敛。调用图 SCC 迭代到不动点（在上限内），使相互递归函数能拿到准确摘要。
4. **排序、去重、输出**：按 严重度 × 证据强度 × 源类可利用性 打分，并输出到控制台、JSON 或 SARIF。

检测器家族：污点（跨文件 source→sink，含 SQLi、XSS、命令/代码执行、反序列化、SSRF、路径穿越、格式串、加密、LDAP 注入、XPath 注入、HTTP 头/响应拆分、开放重定向、服务端模板注入、XXE、原型污染、数据外泄、以及 auth 折入的能力位类规则）、CFG 结构（鉴权缺失、未守卫汇、资源泄漏）、状态模型（use-after-close、double-close、must-leak、unauthed-access）、AST 模式（tree-sitter 结构匹配）。完整检测器文档：[Detectors](https://elicpeter.github.io/nyx/detectors.html)。

---

## 配置

配置由 `nyx.conf`（默认值）与 `nyx.local`（你的覆写）合并而成，从平台配置目录读取（Linux 为 `~/.config/nyx/`，macOS 为 `~/Library/Application Support/nyx/`，Windows 为 `%APPDATA%\elicpeter\nyx\config\`）。

```toml
[scanner]
mode         = "full"        # full | ast | cfg | taint
min_severity = "Medium"

[server]
host = "127.0.0.1"
port = 9700
open_browser = true

# 项目专属净化器
[[analysis.languages.javascript.rules]]
matchers = ["escapeHtml"]
kind     = "sanitizer"
cap      = "html_escape"
```

或交互式添加规则：`nyx config add-rule --lang javascript --matcher escapeHtml --kind sanitizer --cap html_escape`。能力位（caps）：`env_var`、`html_escape`、`shell_escape`、`url_encode`、`json_parse`、`file_io`、`fmt_string`、`sql_query`、`deserialize`、`ssrf`、`data_exfil`、`code_exec`、`crypto`、`unauthorized_id`、`ldap_injection`、`xpath_injection`、`header_injection`、`open_redirect`、`ssti`、`xxe`、`prototype_pollution`、`all`。完整 schema：[Configuration](https://elicpeter.github.io/nyx/configuration.html)。运行 `nyx rules list` 可在终端浏览注册表。

---

## 状态

正在积极开发中。API、检测器行为、配置项可能在版本间发生变化。507 案例语料上的规则级 F1 是 CI 回归下限；分语言详情见 [`tests/benchmark/RESULTS.md`](tests/benchmark/RESULTS.md)。

污点分析是过程间的。持久化的每函数 SSA 摘要带有按返回路径的变换与参数粒度的指向集，调用图 SCC（包括跨文件 SCC）迭代到联合不动点。默认 `balanced` 画像还会对文件内被调用做 k=1 上下文敏感内联。Symex（含跨文件与过程间帧）以及按需后向遍历是可选项。可分别用 `--symex` 与 `--backwards-analysis` 单独开启，或通过 `--engine-profile deep` 一并开启。

局限：
- 过程间精度是有界而非无限的。上下文敏感内联为 k=1 且有被调用体大小上限，SCC 不动点有迭代上限。引擎触达上限时回退到摘要，并在发现上记录 `engine_note`。
- 不跨语言追踪调用（FFI、子进程、WASM）。每种语言独立分析。
- 几项语言特性未建模：宏、大多数动态分派、别名导入、反射。
- C/C++ 处于预览梯度。当前已跟踪 STL 容器流、builder 链、内联类成员函数；深度指针别名与函数指针未跟踪。干净报告不应被理解为干净审计。在作为硬性 CI 门禁之前，请与基于 clang 的工具搭配使用。
- 结果可能含误报或漏报；预期需要人工复核。

---

## 文档

完整文档站点：**[elicpeter.github.io/nyx](https://elicpeter.github.io/nyx/)**。

- [Quick Start](https://elicpeter.github.io/nyx/quickstart.html) · [CLI Reference](https://elicpeter.github.io/nyx/cli.html) · [Installation](https://elicpeter.github.io/nyx/installation.html)
- [`nyx serve`](https://elicpeter.github.io/nyx/serve.html) · [Output Formats](https://elicpeter.github.io/nyx/output.html) · [Configuration](https://elicpeter.github.io/nyx/configuration.html)
- [How it works](https://elicpeter.github.io/nyx/how-it-works.html) · [Detectors](https://elicpeter.github.io/nyx/detectors.html)（[Taint](https://elicpeter.github.io/nyx/detectors/taint.html)、[CFG](https://elicpeter.github.io/nyx/detectors/cfg.html)、[State](https://elicpeter.github.io/nyx/detectors/state.html)、[AST Patterns](https://elicpeter.github.io/nyx/detectors/patterns.html)）
- [Rule Reference](https://elicpeter.github.io/nyx/rules.html) · [Language Maturity](https://elicpeter.github.io/nyx/language-maturity.html) · [Advanced Analysis](https://elicpeter.github.io/nyx/advanced-analysis.html) · [Auth Analysis](https://elicpeter.github.io/nyx/auth.html)

---

## 参与贡献

欢迎贡献。

Nyx 是开源项目，并将永远保有完全开源的核心。为了支持长期开发并使项目可持续，贡献者在首次合入前可能会被要求签署 Contributor License Agreement。

提交前请运行 `sh scripts/check.sh`。完整指南（包括如何添加规则与支持新语言）见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。崩溃、panic 或可疑结果请提 issue，附最小复现片段与 Nyx 版本号。

---

## AI 披露

- **引擎代码**（taint、SSA、CFG、调用图、抽象解释、符号执行）：以人工编写为主。AI 仅用于有选择的重构与样板代码，所有合入均经人工审阅。
- **文档与本 README 的大部分内容**：由 AI 基于代码生成并经人工编辑。文档与代码漂移请作为 bug 上报。
- **测试用例与 `expected.yaml` 文件**：AI 协助起草，落库前经人工审核。
- **前端 UI**（React 应用）：在 AI 协助下构建，经人工审阅。

与任何静态分析器一样，在把 Nyx 用作 CI 门禁前，请基于你自己的语料验证发现。

---

## 许可证

GNU General Public License v3.0 或更高版本（GPL-3.0-or-later）。可选的 `smt` 特性会捆绑 Z3（MIT 许可）；分发以 `--features smt` 构建的二进制时，应在归属信息中包含 Z3 的许可证。完整文本见 [LICENSE](./LICENSE)；第三方依赖见 [THIRDPARTY-LICENSES.html](./THIRDPARTY-LICENSES.html)。
