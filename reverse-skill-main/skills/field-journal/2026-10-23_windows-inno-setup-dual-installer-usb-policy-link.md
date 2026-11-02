# 2026-10-23 Windows 双安装包 USB 管控链联动逆向（Delphi + VB6 + 内核 minifilter）

## 场景分类
二进制分析 / Windows 安装包解包 / 端点管控策略还原 / 内核 minifilter

## 目标概述
对两个 Inno Setup 安装包做纯静态分析，还原「USB 安全盘制作工具」与「终端安全管控软件」之间的生产者—校验者联动，并解释某军政内网为何强制要求特定版本 USB 介质。

## Scope 摘要（脱敏）
- auth_basis: 用户直接提供自有安装包并要求分析
- network_profile: offline（全程未安装、未执行、未联网）
- asset_types: [PE32 installer (Inno Setup), Delphi x86 GUI, VB6 native EXE, kernel minifilter sys, config.ini]

## 角色
- lead_role: lead
- specialists: []

## 完整执行链路
1. 先读 `skills/reverse-skill-router/SKILL.md` 与各子 skill 的触发条件，确定走「解包 → 静态字符串 → PE 元数据 → 反汇编」路线，不做动态执行。
2. 用 `innounp` 解包两个安装包，得到 `install_script.iss`（Inno 脚本），从中直接拿到：安装的 exe/dll/驱动清单、服务名、配置文件路径与默认值、`.myp` 文件关联。
3. 写 `work/pe_info.py`（pefile）读取架构/节/导入表；写 `work/delphi.py` 解析 PE 中 Delphi `UnicodeString` 记录以还原常量字符串地址表。
4. 写 `work/strx.py` + `work/grepstr.py` 做 ANSI/UTF-16 双编码字符串抽取，定位关键词：`usb_no_at`、`An toan`、`USB-AT`、`inf.bin`、`Mtext.bin`、GUID、`CryptAcquireContext`。
5. 写 `work/disr.py`（capstone）做带字符串自动注释的反汇编器。按「调用点 → 目标函数」两跳定位核心决策函数。
6. 沿调用链逐层还原：驱动枚举循环 → 策略判定 → 介质分类（3 个 tier）→ 配置文件查表 → 锁盘调用 → 弹窗 → 日志。
7. 反向侧同样静态抽取 VB6 程序的字符串表与 API 声明，重建其「格式化 → 写标记文件 → 设 ACL → attrib」的产出流程，与消费侧逐字段对齐。
8. 生成 SVG 图（纯 Python 手写 SVG，避免依赖 mermaid-cli / node）与完整报告。

## Evidence 链摘要（脱敏）
| E-id | severity | status | source_type | 可复用命令模式 | 关联 Finding |
|------|----------|--------|-------------|----------------|--------------|
| E-001 | info | observed | command | `innounp -x -q -y "-dext\A" setup.exe` | F-01, F-02 |
| E-002 | info | validated | command | `python work\disr.py <pe> 0x90ECE0 120` | F-01, F-03 |
| E-003 | info | validated | command | `python work\grepstr.py strings.txt "inf\.bin"` | F-04 |

## Finding / Path 摘要
- top_finding: 两个安装包构成同一套「介质指纹—策略查表—内核锁盘」闭环，管控方为消费者、工具方为生产者
- path_type: callflow
- path_one_liner: 制作工具写入介质指纹 → 管控软件枚举 removable 盘并校验指纹 → 读 config.ini 策略 → 命中则调 minifilter 阻断 CreateFile/WriteFile/MoveFile 并弹窗

## 踩坑记录
| 问题 | 原因 | 解决方案 | 耗时 |
|------|------|---------|------|
| 想直接渲染报告里的 Mermaid 图失败 | 本机无 node/mmdc | 改用纯 Python 手写 SVG 生成器，输出独立可用的 .svg | 20m |
| 证据文件写入被占用 | 编辑器进程锁文件 | 换新文件名落盘（E-003 → E-004） | 2m |
| 字符串全是 UTF-16，grep 全部漏掉 | 未做编码区分 | 同时导出 ANSI 与 UTF-16 两份并合并检索 | 10m |
| 关键判断散落在多处，容易误判「4 个文件即可」 | 反汇编有多个近似分支 | 以「计数寄存器 == 5」为准，并画出条件表 | 30m |

## 工具链发现
- `innounp` 解包 Inno Setup 最快，且能直接导出 `install_script.iss`（含默认值配置）。
- Delphi 程序的常量字符串可用 `UnicodeString` 记录（长度前缀 + UTF-16 + 引用计数）批量还原，配合 capstone 注释后阅读效率极高。
- VB6 native 编译产物里 API 名与命令行模板仍以明文留在字符串表，可直接读出 `format.com` 参数、ACL 权限位、WMI 类名。
- 「锁盘」这类结论必须落到 minifilter GUID / FSCTL 与驱动文件名上，否则容易误判为「只是隐藏图标」。

## 关键代码/命令
```powershell
innounp.exe -x -q -y "-dext\MiAV" setup.exe
innounp.exe -x -q -y "-dext\USB"  setup2.exe
python work\disr.py "ext\MiAV\{app}\MiAV.exe" 0x90ECE0 120
python work\grepstr.py work\strings_vb.txt "USB-AT2\.6|inf\.bin|Mtext\.bin"
```

## 对本包的改进建议
- 建议在 `skills/windows-pe`（或 binary 分析类 skill）中补一节「Inno Setup 静态解包 + install_script.iss 优先读」：配置默认值常常直接给出策略根因，比反汇编快一个数量级。
- 建议补充「Delphi `UnicodeString` 常量表自动还原」脚本到 tool-index。
- 建议为「双安装包联动分析」提供一个 checklist：生产侧产物清单 ↔ 消费侧校验项，做成逐字段矩阵。

## 可复用的模式/脚本片段
- `work/delphi.py`：解析 PE 资源段，导出全部 UnicodeString 常量 → 地址映射，供反汇编自动注释。
- `work/disr.py`：`python work\disr.py <pe> <offset> <count>`，输出带字符串内联的 Capstone 反汇编。
- 「指纹矩阵」方法：把 A 程序写出的文件名/标签/ACL 与 B 程序校验的字段列成两栏对照表，差异点即为兼容性问题所在。

## 进化动作
- [ ] 更新了路由矩阵
- [ ] 更新了 tool-index
- [ ] 更新了 bootstrap-manifest
- [ ] 更新了子 skill 文档
- [ ] 新增了 pitfalls 记录
- [x] 无需更新

## 环境信息
- OS: Windows 11 (win32 10.0.26300)
- 工具版本: innounp 2.71.2 / pefile / capstone / Python 3.x
- 目标平台/版本: Windows x86-32，Inno Setup 6.6.1 与 6.1.0

## 脱敏要求
> 本文件可能随仓库同步到远程，必须脱敏。完整规范见 [`anonymization.md`](anonymization.md)。

- 厂商/产品名：统一替换为 `{vendor}`、`{endpoint_suite}`、`{safe_media_tool}`
- 单位、军政背景：统一替换为 `{unit}`
- 具体偏移量、magic 值、配置键名：保留技术内容但去除厂商标识（`USB-AT2.6` → `{label_magic}`，GUID → `{minifilter_guid}`）
- 文件路径：去除真实用户名与安装根路径

## 索引同步（提交前最后一步）
1. 「二进制 / 固件 / CTF」小节新增一行
2. 「高频成功模式（按技术）」新增「安装包联动分析」小节
3. 「实体倒排（按目标特征）」新增「Inno Setup 双包联动」
4. 更新累计统计与最近更新日期

---
<!-- [进化统计] 本包累计完成项目: 22 | 本次新增模式: 1 | 本次修复工具链问题: 1 -->
<!-- [社区贡献] 完成后询问用户是否 PR 到主仓库。流程见 CONTRIBUTE-BACK.md -->
