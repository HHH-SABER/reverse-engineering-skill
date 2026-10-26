# 安装器与载荷分析（自解压包 / 竞品样本拆解）

方法论实测自：360免费WiFi 校园版自研安装器、WiFi共享大师（NSIS）、WiFi共享精灵（自研 TXZ 容器）、"WiFi助手"（Inno 200MB 捆绑包）。

## 通用流程

1. **秒级侦察**：`python scripts/pe_recon.py 目标.exe` → 节表熵、overlay、版本信息、导入表、RCDATA 大块、安装器/壳/技术路线特征，一次出齐。
2. **判定形态**（三条线索交叉）：
   - `.rsrc` 占 90%+ 体积且熵≈8 → 自解压型，载荷在资源段（重点看 RT_RCDATA 大块）
   - 小 stub（<2MB）+ 大 overlay → NSIS/Inno/自研下载器，载荷在文件尾
   - 纯 MSI → lessmsi/Orca 解包
3. **按魔数提取载荷**：`37 7A BC AF 27 1C`=7z（py7zr/7z 解）、`MSCF`=CAB（expand）、`PK`=zip、`Rar!`=RAR、非标准魔数（如 TXZ）=自研容器，需逆向其压缩头。
4. **先读行为脚本再逆向代码**：自研安装器常带 XML/INI 行为脚本（安装路径、快捷方式、装完执行的命令行参数、捆绑项）——读完脚本安装流程就全明了，剩下的代码逆向只是验证。例：360 安装器的 `config.xml` 里 `Pid="freeap_school"`、`<Exec Param="/preinstallfree /school">` 全是行为。
5. **技术路线静态判别**（以 WiFi 共享类为例，其他领域同理：找必然出现的关键 API/文件名）。领域特征**不写进通用脚本**，用 `--markers` 注入：把「特征<TAB>含义」逐行写进 `markers-wifi.txt`（十六进制特征写成 `hex:377ABCAF271C<TAB>7z 载荷`），跑 `python scripts/pe_recon.py 目标.exe --markers markers-wifi.txt`。下面就是 WiFi 共享类的现成清单：
   - `wlanapi`/`WlanHostedNetwork*` → Hosted Network 老路线（Win10 1607+ 已弃用）
   - `hnetcfg`/`INetSharing`/`ICSDHCP.dll` → ICS 共享路线
   - `Tethering` 字符串 → WinRT 现代移动热点路线
   - 自带 `.sys`（如 `*nat*.sys` + `.inf` + `.cat`）+ DIFxAPI → 自研内核 NAT 驱动路线
   - `RaAPAPI`/`RtlLib`/`AP_API_IHV`/`HWID.ini`/`APDefault.ini` → Realtek OEM SoftAP SDK 血统
6. **产出报告格式**：身份表（产品/版本/签名/编译时间）→ 容器结构 → 行为链（装什么、跑什么、连什么网）→ 值得借鉴 / 避坑点。

## 血统判定（多样本对比）

同源产品会复用同一套 SDK 文件名与结构：把两个样本解包后对比内层文件名（`RtlLib.dll`、`netsf.inf`、`ICSDHCP.dll`、`APDefault.ini`……），同名即同血统——360免费WiFi 与 WiFi共享大师实为同一套 Realtek OEM SDK 的两次包装。识别血统后可直接复用已知分析结论，省一半工作量。

## 避坑清单（来自真实样本）

- 无签名 + 巨型压缩体（如 200MB Inno）≈ 捆绑全家桶，静态信息量为零，不值得深挖，定性即可
- 自研容器（非标准魔数）是防直接解包的障眼法：先找解包 stub 的逻辑，或者干脆运行后在 Procmon 看它往哪儿写文件（VM 内）
- 捆绑与推广痕迹（MiniNews/弹窗 dll、杀进程插件 FindProcDLL/KillProcDLL）是判断"这软件值不值得信任"的快速指标
- 竞品主程序用 wke/CEF 内嵌网页做 UI 时，逆向价值在网页资源（HTML/JS）而不是二进制
