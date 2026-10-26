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

## 使用边界

只用于学习与研究：CTF、crackme、自有软件、已授权安全评估、防御性分析（病毒分析、漏洞复现）。不协助盗版破解商业软件用于未授权使用、开发恶意软件、未授权入侵他人系统或账号。

## 许可

本仓**暂未声明开源许可**（默认保留所有权利）。若要开源请先确认：技能正文为你本人原创；`references/corpus-index.md` 仅为第三方文章标题的索引，不含文章正文，但语料本身另有版权归属，见 [docs/CORPUS.md](docs/CORPUS.md)。
