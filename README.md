# reverse-engineering-skill

**逆向工程实战技能包** —— 中文语料检索 · 安装器/自捆绑拆解 · 中文遗留技术栈 · 新手教学。

面向 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（DSH）等支持 `SKILL.md` 约定的 agent 运行时。

> 本仓只放**技能框架**。配套的第三方语料（吾爱破解精华集蒸馏，411 篇）体量与版权原因单独放在私有仓 `reverse-engineering-corpus`，接入方式见 [docs/CORPUS.md](docs/CORPUS.md)。

---

## 这个技能负责什么

它**不**做通用逆向（脱壳、反调试、IAT 修复、VMP、安卓、游戏内存、恶意样本、pwn/内核、固件、取证、JS 反混淆）——那些路由给更成熟的 `reverse-engineer-anything`（REA）与 `reverse-skill`。

它专做四件事：

| 场景 | 入口 |
|---|---|
| 从中文实战语料里找原文与案例 | `references/corpus-index.md` |
| 拆安装器 / 自解压包 / 竞品捆绑、判定血统、提取载荷 | `references/installer-analysis.md` |
| 易语言 / Delphi / VB p-code / 16 位 NE / Java jar | `references/chinese-legacy-stacks.md` |
| 新手学习路线、讲透某篇文章、出练习题 | `SKILL.md` 的「教学模式」 |

设计取向：**把已被上游覆盖的领域让位，只保留语料与中文遗留栈这两个别人没有的资产**。v2.0.0 起有意收窄，详见 [CHANGELOG](skills/reverse-engineering/CHANGELOG.md)。

## 安装

把技能目录放进运行时的技能根。以 DSH 为例：

```bash
git clone https://github.com/HHH-SABER/reverse-engineering-skill.git
# 把 skills/reverse-engineering 整个目录拷进技能根
#   Windows: %USERPROFILE%\.dsh\skills\reverse-engineering\
#   *nix:    ~/.dsh/skills/reverse-engineering/
```

要求：技能根**只认一层深**（`<root>/<name>/SKILL.md`），多套一层会静默失效。

装完把私有语料仓也克隆到本地，然后设置环境变量指向它：

```bash
# Windows (PowerShell)
setx RE_CORPUS_ROOT "D:\corpus\reverse-engineering-corpus\wuaipojie-distilled"
# *nix
export RE_CORPUS_ROOT="$HOME/corpus/reverse-engineering-corpus/wuaipojie-distilled"
```

不设 `RE_CORPUS_ROOT` 时，技能会询问语料位置——**不会静默跳过**。

## 目录结构

```
.
├── CATALOG.md                  ← 技能分类表（分类的唯一真值）
├── docs/
│   ├── CLASSIFICATION.md       ← 分类规则：目录轴、命名、何时新建分类
│   ├── NEW-SKILL.md            ← 新增技能流程 + 自检清单
│   └── CORPUS.md               ← 语料仓怎么接
└── skills/
    ├── _template/              ← 新技能骨架，复制即用
    └── reverse-engineering/    ← 现有技能
```

分类规则摘要：**目录平铺 `skills/<skill-name>/`，分类写在 `CATALOG.md` 的表格里**。原因见 [CLASSIFICATION](docs/CLASSIFICATION.md#为什么不用分类子目录)。

## 后续新增技能

```bash
cp -r skills/_template skills/my-new-skill
# 填 frontmatter、写正文、在 CATALOG.md 加一行
```

逐步说明与检查清单见 [docs/NEW-SKILL.md](docs/NEW-SKILL.md)。

## 许可

本仓**暂未声明开源许可**，默认保留所有权利（All rights reserved）。若后续要改为开源许可，请先确认：`skills/` 下的技能正文、`docs/`、`skills/_template/` 均为本人原创。

## 第三方内容与免责声明

本仓内**唯一的第三方内容**是 [`skills/reverse-engineering/references/corpus-index.md`](skills/reverse-engineering/references/corpus-index.md)——约 120 篇中文逆向实战文章的**标题与主题归类索引**。

- **它只含标题与分类标签**，不含任何文章正文、配图、附件或破解工具。
- 被索引文章的**著作权归原作者与吾爱破解论坛（52pojie）所有**。本仓对这些标题的使用属于**指路性引用**（便于读过原帖的人定位原文、记录哪个技术点值得查原文），**不构成转载授权**，也不代表原作者或论坛对本仓的认可或背书。
- **本仓不是这些文章的分发渠道。** 配套语料正文放在私有仓，不对外开放；本仓不含也无法重建原文。
- 需要阅读原文时，请回到**原作者发布的原始地址**；不要依赖任何第三方副本。
- 本仓的脚本与分析方法是通用技术内容，**不附带任何样本、破解产物或许可证密钥**。

**侵权处理**：若权利人认为本索引或本仓其它内容构成侵权，请通过 GitHub Issue 或仓库主页邮箱联系，确认后我会**立即删除相关内容**，不设前置条件。

## 使用边界

本项目面向**学习与研究**：CTF、crackme、自有软件、已授权的安全评估、防御性分析（恶意样本分析、漏洞复现）。**不协助**：盗版破解商业软件用于未授权使用、开发恶意软件、未授权入侵他人系统或账号。语料中涉及网游作弊的内容，仅作为协议与内存原理的学习材料，涉及对抗他人服务器时请自行评估风险与合规边界。
