# CHANGELOG

本技能包的变更记录（语义化版本）。**源真身 = 本目录**；改动后运行
`powershell -ExecutionPolicy Bypass -File scripts/sync_skill.ps1` 同步到各安装副本与 zip。

## [2.0.0] - 2026-10-20 · 收窄（breaking：职责边界变化）

### Changed

- **技能收窄为 4 块独有内容**：411 篇 52pojie 语料检索、安装器/自捆绑/血统判定、中文遗留技术栈、逆向教学。
- `SKILL.md` 新增「先判断：这个任务归谁」路由表；`description` 收窄（不再触发"脱壳/反调试/安卓/游戏/病毒"等通用词，避免与上游技能抢路由）。
- `README.md` 改为「负责什么 / 不负责什么」双列表；结构说明更新为 9 文件。
- `references/test-prompts.md` 7 条 → **9 条**：T3 改为「让位路由正确性」，新增 T8（中文遗留栈）、T9（不重复造轮子）。

### Added

- `references/chinese-legacy-stacks.md`：易语言 / Delphi / VB p-code / 16 位 NE / Java jar + 中文环境特有坑。
- `CHANGELOG.md`（本文件）+ frontmatter `metadata.version`。

### Removed（归档，未删除）

- 移出 7 个已被上游技能覆盖的 reference：`windows-re.md`、`android.md`、`game.md`、`malware.md`、`web-js.md`、`exploit.md`、`tools.md`。
- 归档位置：本机 `_archive/2026-10-20-narrowed/`（含 7 份原文 + 旧快照，**未随本仓分发**；需要时向仓库维护者索取）。
- **原因**：`zhaoxuya520/reverse-skill`（★42,747、MIT、44 条配置化路由、175 条回归、双平台 CI）与 REA 已完整覆盖这些领域，继续维护属重复劳动。逐条判定表见 Obsidian `人工筛选并试用的插件与技能` 第 34 条。

## [1.1.0] - 2026-10-16 · 正确性与可用性修复

### Fixed

- README 语料路径缺 `01_语料归档`，指向不存在的目录。
- 「源真身」自相矛盾：`sync_skill.ps1` 注释称 live 目录为真身，`SKILL.md` 称本目录为真身 → 统一为**本目录**，脚本方向改为 包 → live + zip。
- 语料篇数 `412` → **`411`**（2019:211 / 2020:166 / 补采:34，口径见语料 `INDEX.md` 与 `LEDGER.md`）；索引「约 90 篇」→「约 120 篇」。
- `corpus-index.md` 删除重复且误分类的 `04_24_` 条目。
- `pe_recon.py` 在 GBK 控制台下打印中文/箭头直接 `UnicodeEncodeError` 崩溃（旧版 latin-1 解码 overlay + 未设 stdout 编码）。
- 版本信息中文乱码（pefile 返回 UTF-8 字节，旧代码按 latin-1 解）。
- `--markers` 文件带 UTF-8 BOM 时首行失效 → 改 `utf-8-sig` 读取。
- `sync_skill.ps1` 的中文注释被 PowerShell 5.1 按 ANSI 解析，`param()` 直接语法错误 → 全文件改为 **ASCII-only**。

### Added

- `pe_recon.py` 重写为两档：**零依赖档**（stdlib 解析文件头/节表熵/overlay/导入表/打包指示器/壳指纹）+ 可选 **pefile 增强档**（资源树 RT_RCDATA / 版本信息）。
- `pe_recon.py` 新增 `--json` / `--markers` / `--max-scan` / `--selftest`（18 项自检）；特征扫描改为单遍多模式；退出码 0/1/2 语义化；非 PE 输入识别格式而非抛 traceback。
- 新增打包指示器：入口点在节外、W+X 节、虚拟占位节、高熵节/高熵 overlay、导入函数过少、资源占比、TLS 回调、Rich header、ASLR/DEP/CFG、**证书表与 overlay 分离**。
- 语料根支持环境变量 `RE_CORPUS_ROOT` 覆盖；README/SKILL 补 DSH 安装行与「与 REA 并存」说明。
- `sync_skill.ps1` 支持多目标（自动探测已存在的 `$DSH_HOME/skills` 与 `~/.zcode/skills`）+ `-WhatIf` / `-SkipLive` / `-LiveDir`，结束输出每个目标文件数与 zip SHA256。

## [1.0.0] - 2026-10-16 · 基线

首次纳入版本管理时的快照：`SKILL.md` + `README.md` + 10 个 `references/` + 2 个 `scripts/`，语料 411 篇，zip 与包目录一致。
