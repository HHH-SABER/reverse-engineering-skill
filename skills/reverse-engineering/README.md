# reverse-engineering 技能安装包

**52pojie 中文实战语料检索 + 安装器/自捆绑拆解 + 中文遗留技术栈 + 逆向新手教学。**

> ⚠️ **2026-10-20 起本技能有意收窄。** 通用逆向（脱壳/反调试/安卓/游戏/恶意样本/JS/取证/固件/pwn）已被更成熟的第三方技能完整覆盖，继续维护等于重复造轮子。本技能只保留四块不可替代的内容，其余任务一律路由出去；被移除的 7 个 reference 归档在 `_archive/2026-10-20-narrowed/`。

## 它负责什么（以及不负责什么）

| ✅ 负责 | ❌ 不负责（去哪） |
|---|---|
| 411 篇吾爱破解精华语料的检索与原文回读 | 脱壳 / 反调试 / IAT / VMP / .NET 混淆 → `reverse-skill` |
| 安装器、自解压包、竞品捆绑、血统判定 | 安卓 / iOS → `reverse-skill` 的 `apk-reverse` / `mobile-reverse` |
| 易语言 / Delphi / VB p-code / 16 位 / Java jar | 游戏内存 / 反作弊 / Unity / il2cpp → `reverse-skill` R0 |
| 教学模式（新手路径、讲解、练习） | 恶意样本 / YARA / 宏 / C2 → `reverse-skill` 的 `malware-analysis` |
| | pwn / 内核 / 固件 / 取证 → `reverse-skill` 对应模块 |
| | 需要严格证据链（Evidence ID / 覆盖度 / 未知项）→ `reverse-engineer-anything`（REA） |

## 结构（8 个文件）

```
reverse-engineering-skill/
├─ SKILL.md                       总纲：先判断归谁 + 语料 + 安装器 + 遗留栈 + 教学
├─ README.md                      本文件（安装说明）
├─ references/
│  ├─ corpus-index.md             约 120 篇精选索引（语料根路径的唯一定义处）
│  ├─ installer-analysis.md       安装器/载荷拆解流程与避坑清单
│  ├─ chinese-legacy-stacks.md    易语言/Delphi/VB p-code/16 位/Java jar
│  └─ test-prompts.md             回归提示词 T1~T9
└─ scripts/
   ├─ pe_recon.py                 PE 秒级侦察（零依赖档 + 可选 pefile 增强档）
   └─ sync_skill.ps1              同步到各安装副本 + 重打包 zip
```

归档的 7 个 reference（`windows-re` / `android` / `game` / `malware` / `web-js` / `exploit` / `tools`）在
`_archive/2026-10-20-narrowed/`：需要时仍可读，但**不随技能分发、不再维护**。

## 安装方法

**目录名必须是 `reverse-engineering`**（与 SKILL.md 里的 `name` 一致），把整个文件夹放进对应技能目录即可：

| 工具 | 用户级（所有项目可用） | 项目级（仅当前项目） |
|---|---|---|
| DeepSeek Harness（DSH） | `$DSH_HOME/skills/reverse-engineering/`（本机 `C:\Users\<用户名>\.dsh\skills\`） | `<项目>/.dsh/skills/reverse-engineering/` |
| ZCode | `~/.zcode/skills/reverse-engineering/` | `<项目>/.zcode/skills/reverse-engineering/` |
| 跨工具通用（Claude/Codex/Cursor 等） | `~/.agents/skills/reverse-engineering/` | `<项目>/.agents/skills/reverse-engineering/` |

（`~` = 用户主目录，Windows 即 `C:\Users\<用户名>`。DSH 动态扫描 `$DSH_HOME/skills`，装完**当次会话即可加载**；其它工具通常要重启/新开会话。）

> 各 agent 的技能目录并不通用。装到新工具前先确认它实际扫描哪个目录，装完再用该工具的技能列表确认能被加载——**加载不到等于没装**。

> **与 REA（`reverse-engineer-anything`）并存不冲突**：那个是 REA MCP 工具服务器的使用说明（怎么连工具、怎么取证据），本技能是方法论 + 中文语料 + 安装器拆解。典型分工：REA 取静态/运行时证据，本技能用语料对照经验并出报告。

## 脚本依赖

`scripts/pe_recon.py` 有两个档位，自动选择（安装器拆解第一步必用）：

- **零依赖档（默认可用）**：仅标准库——格式识别、文件头、节表熵、overlay、入口点与节权限、导入表、打包指示器、通用壳/容器指纹。
- **增强档（可选）**：`pip install pefile` 后追加资源树（RT_RCDATA 大块载荷）与版本信息。

裸 PE 任务先跑：`python scripts/pe_recon.py 目标.exe`。常用开关：`--json`（机器可读）、`--markers extra.txt`（注入领域特征）、`--max-scan N`、`--selftest`（18 项自检，无需样本）。

`scripts/sync_skill.ps1` 把本目录同步到所有已存在的安装副本并重打包 zip。

## 触发方式

提到这些时自动触发（**注意：刻意不含"脱壳/反调试/安卓/游戏/病毒"等通用词**，那些交给上游技能）：
吾爱破解语料、52pojie 精华、逆向文章检索、安装器拆解、自解压包、捆绑软件分析、竞品血统、易语言、Delphi、VB p-code、16 位程序、逆向入门/学习路线。

## 关于语料原文（可选依赖）

语料根路径**只在 `references/corpus-index.md` 顶部定义一处**，其余文件引用它。本机默认：

`<corpus-root>/`

- **本机安装**：路径已就绪，agent 做任务时会按索引读原文（图文含完整操作细节），效果最佳。
- **其它机器安装**：没有语料库也能用（SKILL.md 与各 reference 自足），但会失去「回读原文」能力。语料换了位置时**设置环境变量 `RE_CORPUS_ROOT`** 指向实际根目录即可，不必改文件。
- 附件与样本：语料根上一级有 `附件\` 与 `附件索引.md`。

## 使用边界

技能内含使用约束：仅限学习与研究（CTF、crackme、自有软件、已授权评估、防御性分析），不用于盗版破解、恶意软件开发或未授权入侵。

## 维护

- **源真身 = 本目录**：所有编辑都在本目录进行，再同步到各 agent 的安装副本与 zip；不要反过来直接改安装副本再覆盖本目录。
- 改完运行 `powershell -ExecutionPolicy Bypass -File scripts/sync_skill.ps1`——默认镜像到**所有已存在**的安装副本（`$DSH_HOME\skills\`、`~\.zcode\skills\`）+ 重打包 zip，结束输出每个目标文件数与 zip 的 SHA256。`-WhatIf` 只预览，`-SkipLive` 只重打包，`-LiveDir <路径[,路径]>` 指定目标。
  - 脚本刻意保持 **ASCII-only 注释**：Windows PowerShell 5.1 会把「无 UTF-8 BOM 的 .ps1」当 ANSI 读，中文注释会导致解析失败（`意外的标记 )`）。
  - 本机默认禁止运行脚本时，`-ExecutionPolicy Bypass` 是必需的（或先 `Set-ExecutionPolicy -Scope Process Bypass`）。
- 改动较大时跑 `references/test-prompts.md` 里的 T1~T9 回归提示词。
- **不要再加通用逆向正文**：该领域若已被 `reverse-skill` / REA 覆盖，只加一行路由，不加内容。
