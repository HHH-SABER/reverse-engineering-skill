# template-skill

<!-- 复制后必须改：标题、解决的问题、安装位置 -->

一句话说明这个技能解决什么问题、给谁用。

## 负责什么

| 场景 | 入口 |
|---|---|
| … | `references/…` |
| … | `SKILL.md` 的「…」 |

## 不负责什么

脱壳、反调试、…… 请用 `<别的技能>`。

## 安装

把本目录拷进运行时的技能根（**只能一层深**）：

```
<skills-root>/template-skill/SKILL.md
```

## 依赖

- 外部工具：无 / `python 3.10+` / …
- 语料：无 / `<语料集合名>`（见仓库根 `docs/CORPUS.md`）

## 目录

```
template-skill/
├── SKILL.md
├── README.md
├── CHANGELOG.md
├── references/
└── scripts/
```

## 使用边界

只用于学习与研究场景。不协助 ……
