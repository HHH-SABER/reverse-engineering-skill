# 中文遗留技术栈（易语言 / Delphi / VB p-code / 16 位 / Java 桌面）

> 这些栈在英文资料里几乎无人整理，但在中文逆向圈子里出现频率很高，是本技能保留下来的独有内容之一。
> 其余通用手法（脱壳、IAT 修复、反调试大全、VMP 对抗）已让位给 `reverse-skill` / REA，完整原文见
> 本机归档的 `2026-10-20-narrowed/references/windows-re.md`（**未随本仓分发**）。

## 识别：先看它是什么栈

| 特征 | 判定 |
|---|---|
| 导入表稀疏、字符串多是中文提示、目录里有 `*.fnr` | **易语言** |
| `@Sysutils@` / `@System@` 前缀符号、VMT/RTTI 结构、`System.pas` 字样 | **Delphi** |
| 导入 `MSVBVM50.dll` / `MSVBVM60.dll`，`.frm` 相关字符串 | **VB6**（注意分 p-code 与 native） |
| 文件头 `MZ` 但 `e_lfanew` 处不是 `PE\0\0` | **16 位 NE/DOS**（`pe_recon.py` 会直接报"缺少 PE 签名"） |
| `META-INF/MANIFEST.MF` 有 `Main-Class` | **Java jar**（先 `unzip -l` 看结构） |

## 易语言

- **核心支持库不会被 VMP 虚拟化**——这是最省力的突破口：在支持库函数的 `retn` 处下断，堆栈里常能直接看到明文账号/口令，再 `F7` 跟出调用它的关键 call。
- 干扰函数常用 `leave; ret` 填充，可直接跳过。
- 加壳样本**在 Win7 环境脱壳**成功率明显更高（老壳对新系统兼容差）。
- 常见库文件名：`krnln.fnr`、`RegEx.fnr` 等以 `.fnr` 结尾。

## Delphi

- 反编译/识别：**IDR**（Interactive Delphi Reconstructor）或 **DEDE**，函数识别率普遍高于 IDA；可导出 map 再喂给 x64dbg/OD。
- 事件定位：**DeDeDark**，能从 `/` 按钮/菜单事件直接定位到 `TForm` 方法。
- 与 IDA 配合：先用 IDR 生成函数名 map，再回填到调试器。

## VB p-code（VB6 解释型）

- 反编译：**VBExplorer**（兼容性最好）；调试辅助：**WKTVBDebugger**。
- 动态分析：跟 `MSVBVM50.DLL` / `MSVBVM60.DLL`——**ESI = 指令指针、EBP = 变量基址**，参数走栈。
- 变量是 **16 字节 Variant**，首字节 `vt` 判类型：`0x02` 整数、`0x08` 字符串、`0x0B` 布尔、`0x04` 单精度、`0x05` 双精度。
- 与 native 编译的 VB 区分：p-code 版本里每条指令都是对 `MSVBVM` 的调用，native 版本才是正常汇编。

## 16 位 NE / DOS 程序

- **OD / x64dbg 不支持 16 位**，必须 **Win98 虚拟机 + TRW2000**。
- VMware 下 TRW 鼠标失灵：在 `.vmx` 里加 `vmmouse.present = "FALSE"`。
- 这类样本的"脱壳"通常无意义，直接按 NE 头结构手工解析段表更快。

## Java 桌面程序（jar）的补丁式破解

- 定位注册窗口：对 `AbstractButton.setText()` 下断，看调用栈找到设置按钮文案的那个类。
- **最小改动原则**：只重写少数 `public` 方法（让校验返回 `null` / `true`），编译后**替换 jar 内对应 class**，其余条目不动。
- loader 场景：`-Xbootclasspath/p` 抢占 + 在 `ClassLoader.defineClass` 里改 7 字节绕过 RSA 校验（**需 Java 8**；9+ 因模块化不再支持这条）。
- 先 `unzip -l` 看结构，再决定改哪个 class；改完 `jar uf` 回填。

## 中文环境特有坑

- **IDA 打不开中文路径** → 先把样本复制到纯英文短路径再分析。
- **OD 搜中文/UTF-8 字符串**：用 `Ctrl+B` 按十六进制搜（OD 不支持 UTF-8 文本搜索）。
- **多 adb 设备冲突**：先 `adb devices`，把多余设备/模拟器关掉再操作。
- **PE 版本信息里的中文**常是 GBK：`scripts/pe_recon.py` 已按 UTF-8 → UTF-16LE → latin-1 兜底解码。
