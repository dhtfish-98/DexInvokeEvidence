# 本地验证状态

当前项目状态：**本地候选，待独立代码审核；未建 GitHub 仓、未推送、未发行、CVP 资格 OPEN。**

验收目标：自编译 Java→DEX 产生直接、虚、接口、静态和 `/range` 调用；与 Android SDK dexdump 的每个调用点精确对照；数组数据中的调用操作码字节不误报；重签名的畸形长度、偏移和索引明确拒绝。验证脚本把工具版本、工具哈希、样本与源码哈希及每个异常原因写入 `Build/验证/DexInvokeEvidence-20261006/run-*/receipt.json`。

2026-10-06 本地实测（UTC 2026-10-05 20:45）：

- 完整收据：`Build/验证/DexInvokeEvidence-20261006/run-20261005T204535Z/receipt.json`，SHA-256 `6249e37cab5249baf49f594c665faed4bc8f20b57bad84b756fa8549ba087f64`。
- JDK `javac 21.0.12.1`；Android D8 `2.1.7-r1`；验证用 dexdump 二进制 SHA-256 `7173a3cd722c668c96cd9198753c8f506fbfaafdd079ca72e1e4f4187e202213`。
- 自写 Java 样本编译为 3 个 class 和一份 1,788 字节的 DEX 038；DEX SHA-256 `dc19d31f221b89d9706728b94c602d7d0867e6906c4600ceb3903c11535103c2`。
- 8 个调用点与独立 dexdump 的 **文件偏移、方法内代码单元偏移、指令种类、目标方法索引**逐一相同；覆盖 `invoke-direct`、`invoke-virtual`、`invoke-interface`、`invoke-static`、`invoke-static/range`。数组数据中的合成操作码标记出现一次且未计入调用点。
- 8 个指定的畸形样本均拒绝：签名、文件长度、字符串偏移、代码长度、方法索引、类数据 ULEB、数组数据偏移和数组数据长度。其中结构畸形样本已重新计算 DEX SHA-1 与 Adler-32，故不是仅靠哈希不匹配被拒。
- 固定随机种子 `20261006` 的 512 次单字节重签名变异，没有非预期异常：187 次明确拒绝、325 次被结构解析接受。后者只表示解析未发现结构错误，**不表示被变异文件语义正确**。

当前只验证了这一个自编译 DEX 样本及其受控变体；没有真实应用 DEX、运行时调用或权限结果。包构建与隔离安装结果记在下方；工程验证不能代表真实申请任务、实际防护影响或 CVP 审核结果。

包构建与隔离安装：从统一 Build 暂存树成功构建 `dex_invoke_evidence-0.1.0.tar.gz` 与 `dex_invoke_evidence-0.1.0-py3-none-any.whl`。两者分别装入独立 Python 3.14 环境后，在无源码 `PYTHONPATH` 下对同一 DEX 的 JSON 输出完全一致，均为 8 个调用点；错误方法索引通过已安装命令行返回退出码 2。wheel 元数据中的版本为 `0.1.0`，作者邮箱为 `dhtfish98 <109978225+dhtfish-98@users.noreply.github.com>`，许可证表达式为 MIT，内含本项目的许可证。sdist 内含 Java 样本、验证脚本和五份集中项目文档。最终资产文件及其 SHA-256 见 Build 目录的 `package-review.json`；这仅是本地构建测试，没有 GitHub 发行。
