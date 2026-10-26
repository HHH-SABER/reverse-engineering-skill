# 语料仓接入

## 为什么要拆成两个仓

本仓**公开**（技能框架、脚本、我自己写的正文）；语料**私有**（`reverse-engineering-corpus`）。

原因：

1. **版权**。语料是第三方论坛文章（吾爱破解精华集蒸馏，411 篇），我只有阅读与自用的正当性，**没有转发布的授权**。公开上传等于再分发。
2. **体积**。语料 6.89 MB 可接受，但同目录的附件包 4.78 GB、原始 CHM 解包 1.03 GB 完全不能进 git。
3. **节奏**。技能正文按需改；语料只在补充新文章时动。混在一起会让 git 历史变成"改一行正文 + 几百个文件变更"。

## 两个仓的结构对应

```
reverse-engineering-skill/          (public)
├── CATALOG.md                      ← 「依赖语料」列写集合名
└── skills/reverse-engineering/
    └── references/corpus-index.md  ← 语料根路径只在这一处定义

reverse-engineering-corpus/         (private)
├── README.md                       ← 来源与版权声明
└── wuaipojie-distilled/            ← 语料集合（411 篇，平铺）
    ├── 001_*.md   … 212_*.md       ← 2019 篇，NNN_ 前缀
    ├── 01_01_*.md … 07_06_*.md     ← 2020 篇，前两位是分类：
    │                                  01 脱壳破解 02 移动安全 03 病毒木马
    │                                  04 逆向调试 05 数据解密 06 游戏安全 07 其他
    ├── 网络补采/web_*.md            ← 补采 35 篇
    ├── INDEX.md  LEDGER.md          ← 全量索引与容器加密情况
    └── manifest.json  topics.md
```

## 关键约束：语料必须平铺

`corpus-index.md` 用**编号/目录前缀**定位文章（`ls 语料 | grep ^029_`），并在顶部只定义**一处**语料根路径。

因此：

- ✅ 语料目录**保持平铺**，不要按年份/主题分子目录
- ✅ 需要加子目录时，同步修改 `corpus-index.md` 的定位说明
- ❌ 不要把语料复制进 `skills/`——同一份内容两份副本必然漂移

如果将来确实要按年分目录，必须同时更新 `corpus-index.md` 里的两条召回路径（编号定位 + 全文检索），并重跑 `references/test-prompts.md` 的回归提示词。

## 接上之后

克隆语料到本地任意位置，指一个环境变量即可，**不必改任何文件**：

```powershell
# Windows 用户级（新开终端生效）
setx RE_CORPUS_ROOT "D:\corpus\reverse-engineering-corpus\wuaipojie-distilled"
```

```bash
# *nix
export RE_CORPUS_ROOT="$HOME/corpus/reverse-engineering-corpus/wuaipojie-distilled"
```

未设置且默认路径不存在时，技能会**先询问语料位置**再继续，不会静默跳过（这条是硬规则，写在 `SKILL.md` 与 `corpus-index.md` 里）。

## 附件（不入库）

语料目录的同级有 `附件/`（2020 帖子附件包、2023 大附件备份，合计 4.78 GB）与 `附件索引.md`。这些**只留在本地**：

- 单文件常超过 GitHub 100 MB 硬限
- git 无法有效压缩二进制包，会永久膨胀仓库
- 需要样本（crackme / apk / 工具包）时按 `附件索引.md` 在本地查找

## 语料更新流程

1. 新语料蒸馏后，先在**私有语料仓**补充文件（保持命名规范：2019 用 `NNN_`，2020 用 `NN_XX_`，补采用 `网络补采/web_NNNNNNN.md`）
2. 更新语料仓的 `INDEX.md` / `manifest.json` / `LEDGER.md`
3. 回到**本公开仓**，把新增的高价值文章按主题补进 `skills/reverse-engineering/references/corpus-index.md`
4. 更新本仓 `CATALOG.md` 的「依赖语料」备注（如集合名变化）
5. 两边各自提交——**它们没有 submodule 关系**，是一对松耦合的兄弟仓
