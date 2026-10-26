---
name: reverse-engineering
description: 吾爱破解中文实战语料检索 + Windows 安装器/自捆绑拆解 + 中文遗留技术栈（易语言/Delphi/VB p-code/16 位/Java jar）+ 逆向新手教学。当用户要：从 411 篇 52pojie 精华语料里找某主题的原文与案例、拆安装器/自解压包/竞品捆绑并判定血统、处理易语言或 Delphi/VB/16 位老程序、或要一条新手向的逆向学习路径时使用。**通用逆向不在此列**：脱壳、反调试、IAT 修复、VMP、安卓、游戏内存、恶意样本、pwn/内核、固件、取证、JS 反混淆一律先路由到 `reverse-engineer-anything`（REA，工具与证据）或 `reverse-skill`（44 条路由的通用逆向技能包）。
metadata:
  version: "2.0.0"
---

# 逆向工程：语料 · 安装器 · 中文遗留栈

> ⚠️ **本技能在 2026-10-20 被有意收窄。** 原先 10 个 reference 里有 7 个的领域已被更成熟的第三方技能完整覆盖，继续维护等于重复造轮子。那 7 份已归档到 `_archive/2026-10-20-narrowed/`，不再随技能分发；内容需要时仍可读，但**不要在这里继续扩写**。

## 先判断：这个任务归谁

| 任务 | 去哪 |
|---|---|
| 要从语料里找原文 / 案例 / 某技术点的实战文章 | **本技能** → `references/corpus-index.md` |
| 拆安装器、自解压包、竞品捆绑、判定血统、提取载荷 | **本技能** → `references/installer-analysis.md` |
| 易语言 / Delphi / VB p-code / 16 位 NE / Java jar | **本技能** → `references/chinese-legacy-stacks.md` |
| 新手学习路线、讲透某篇语料文章、出练习题 | **本技能** → 下方「教学模式」 |
| 需要**可采信证据**（Evidence ID、覆盖度、未知项） | → `reverse-engineer-anything`（REA，MCP 工具） |
| 脱壳 / 反调试 / IAT 修复 / VMP / .NET 混淆 | → `reverse-skill`（`references/anti-analysis.md`、`tools-advanced.md`） |
| 安卓 APK/so、Frida、加固脱壳、抓包 | → `reverse-skill` 的 `apk-reverse` / `mobile-reverse` |
| 游戏内存 / 反作弊 / Unity / il2cpp | → `reverse-skill` R0（关键词已含 anti-cheat / unity / il2cpp） |
| 恶意样本 / YARA / 宏 / C2 | → `reverse-skill` 的 `malware-analysis` |
| pwn / 内核 / 固件 / 取证 | → `reverse-skill` 的 `pwn-chain` / `firmware-pentest` / `digital-forensics` |

拿不准时的默认动作：**先用 REA 取证据，再回来用语料对照经验**——两者是接力关系，不是替代关系。若本机没装这两个技能，就直接说明"这块已有更成熟的上游技能"，不要把已让位的内容再讲一遍。

## 使用边界

只用于学习与研究场景：CTF、crackme、自有软件、已授权的安全评估、防御性分析（病毒分析、漏洞复现）。不协助：盗版破解他人商业软件用于未授权使用、开发恶意软件、未授权入侵他人系统/账号。网游作弊相关内容仅限学习协议与内存原理，涉及对抗他人服务器时提示风险与合规边界。

## 语料库利用（本技能的核心资产）

**语料根路径只在 `references/corpus-index.md` 顶部定义一处**（避免多处硬编码漂移）。

**语料不随本仓分发**（第三方版权，见仓库根 `docs/CORPUS.md`），所以**没有内置默认路径**：必须由环境变量 `RE_CORPUS_ROOT` 指向本地语料根（通常是私有语料仓的 `wuaipojie-distilled/`），或在 `corpus-index.md` 顶部填你的实际路径。
（2019 编号 `NNN_`，2020 分类 `NN_NN_`，补采 `网络补采/web_*.md`；各年份容器加密情况见语料内 `LEDGER.md`。）**若 `RE_CORPUS_ROOT` 与索引里写的路径都不存在，先向用户询问语料位置再继续，不要静默跳过、也不要在没有语料时假装检索过。**

**两条召回路径，都要用**：

1. **精读索引**：`references/corpus-index.md` 收录约 120 篇按主题分类的高价值文章——接到任务先从这里挑 1~3 篇读原文（图文含完整操作细节）。
2. **全文检索**（索引没覆盖的主题用这个，全量 411 篇）：`rg -l "<关键词>" "<语料根>" -g "*.md"`（rg 缺失时用你所在 agent 的文件搜索工具；Windows 默认没有 grep）。关键词用术语而不是口语（如 `tcache`、`ePortal`、`WlanHostedNetwork`、`VMP`、`令牌桶`），多个关键词分别搜再并集；**语料文件名本身带主题，同时按文件名搜一遍**（如 `04_10_` 是 glibc unlink）。

**附件资产**：语料根目录上一级（`吾爱破解精华集-蒸馏\`）有 `附件\`（2020 帖子附件包、2023 大附件备份）和 `附件索引.md`；部分正文末尾有"配套附件"段落直接链接。需要样本文件（crackme、apk、工具包）时先查这里。

找不到相近主题时再纯按方法论推进。

## 安装器与载荷分析

按 `references/installer-analysis.md` 的流程走。第一步永远是秒级侦察（脚本零依赖即可用）：

```
python <技能目录>/scripts/pe_recon.py 目标.exe
```

出齐节表熵 / overlay / 导入表 / 打包指示器 / 安装器与壳指纹后，再按三条线索交叉判形态（`.rsrc` 占绝对体积 / 小 stub + 大 overlay / 纯 MSI），最后按魔数提载荷、先读行为脚本再逆向代码。领域特征（如 WiFi 共享类的 `wlanapi` / `hnetcfg`）用 `--markers extra.txt` 注入，不写死在脚本里。

**常见误判**：无签名 + 巨型压缩体（200MB 级 Inno）静态信息量为零，**定性即可，不值得深挖**——这条能省掉大量无效工作量。

## 中文遗留技术栈

见 `references/chinese-legacy-stacks.md`（识别表 + 四类栈的突破口）。最值钱的两条：

- **易语言**：核心支持库不被 VMP 虚拟化 → 在支持库 `retn` 处下断，栈里常是明文口令。
- **VB p-code**：ESI=指令指针、EBP=变量基址、16 字节 Variant 首字节 `vt` 判类型。

## 通用硬规则（跨场景仍适用）

1. **地址漂移**：所有地址记"模块基址+偏移"；要跨重启存活就用 AOB 特征码。
2. **动手前先备份**：patch 前复制原件；动态分析先拍快照；改语料/改文件同理。
3. **patch 必须等长**：x86 jmp 占 5 字节；ARM64 NOP = `1F 20 03 D5`。
4. **未知样本不直接跑**：虚拟机 + 断网 + 快照；脚本类载荷先静态解出来看。
5. **教程照抄跑不通**：先理解每步意图，地址/版本/环境不同就得调整。
6. **猜想必须验证**：每个猜测用动态手段证实后再走下一步。

> 完整版（反调试对照表、脱壳到 OEP 的多种大法、IAT 修复全谱、VMP 对抗）在 `reverse-skill` 与归档的 `windows-re.md` 里，这里不重复。

## 分析报告输出规范

完整分析任务（样本拆解、调试记录、竞品研究）按此骨架：**结论先行**（第一句给身份判定/核心结论，不铺垫）→ **证据表**（哈希/魔数/路径/参数/偏移，不贴大段原文）→ **行为链**（按流程叙述，术语与 references 一致）→ **下一步建议**（分"需要用户操作的"和"可继续深挖的"两列）→ **合规提示**（涉及灰区时末尾一句，不说教）。

> 需要严格证据纪律（观察/推断/未知三分、Evidence ID、检索边界）时，交给 REA，别在这里自造一套。

简短问答不套模板，直接回答。

## 教学模式

当用户意图是**学习/理解**而非完成任务（"讲讲这篇脱壳文章"、"给我出个 crackme 练习"、"XX 原理是什么"）时：

- 先从语料里找教材（索引 + 全文检索），以 1~2 篇文章为主线讲解，术语用 references 核对，别凭记忆编造。
- 出练习题时给可验证的判定标准（"输入 X 应得到 Y"），并指明用到的工具与预期路径。
- 讲解收尾给"下一步学什么"，按 corpus-index 的主题从易到难排。

## 维护

**源真身 = 本技能目录**（即包目录 `reverse-engineering-skill/`）；各 agent 下的安装副本（`$DSH_HOME\skills\reverse-engineering`、`~\.zcode\skills\reverse-engineering` 等）与 `reverse-engineering-skill.zip` 都是派生物，不要直接改安装副本再反向覆盖。

改完运行 `powershell -ExecutionPolicy Bypass -File scripts/sync_skill.ps1`（默认镜像到所有已存在的安装副本 + 重打包 zip，结束输出每个目标文件数与 zip 的 SHA256）。改动较大时跑 `references/test-prompts.md` 里的回归提示词。

**不要再往里加通用逆向内容**——先看上方「先判断」表；该领域若已被 `reverse-skill` / REA 覆盖，就只加一行路由，不加正文。
