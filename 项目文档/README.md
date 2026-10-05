# DexInvokeEvidence

DexInvokeEvidence 0.1.0 只读解析授权提供的单个 DEX 文件，列出方法调用指令在文件和方法中的精确位置、指令种类、调用方及 `method_id` 目标。它不运行 APK、Java 或 Dalvik 代码，不判断运行时授权，也不把引用关系等同于实际执行路径。

实现按 Android 官方 DEX 035–040 格式读取固定表、类数据、代码项和指令宽度，检查文件哈希、长度、索引、MUTF-8 字符串、数组/开关数据区域及被扫描代码中的异常处理表。最大输入 64 MiB，总扫描代码预算 2,000,000 个 16 位单元，最多 100,000 个调用点；单个字符串、原型、方法名、累计解码文本与估计输出也有独立预算。超预算、未实现的 `invoke-custom` 或已检查结构的畸形输入会明确拒绝。它不是完整 DEX 合规验证器；输出 JSON 中的目标方法是静态 `method_id` 引用。

本地源码位于 `项目源码/当前项目/research-cvp30-c-20261005/DexInvokeEvidence`；本文档和许可证位于 `项目文档/当前项目/research-cvp30-c-20261005/DexInvokeEvidence`；编译样本、反汇编、畸形样本、收据和包测试统一放在 `Build/验证/DexInvokeEvidence-20261006`。源码目录不保留二进制产物或 Python 缓存。

从项目源码目录运行只读扫描：

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m dex_invoke_evidence /path/to/authorized/classes.dex
```

验证脚本使用自写 Java 样本，依次运行本机 JDK `javac`、Android SDK `d8` 和独立 `dexdump`。它将所有生成文件写入指定 Build 目录，比较调用点的文件偏移、代码单元偏移、调用种类和目标索引，并检查重签名畸形输入失败关闭：

```sh
python3 scripts/validate_live.py \
  --java-home /path/to/jdk/Contents/Home \
  --build-tools /path/to/Android/sdk/build-tools/30.0.3 \
  --output-root /path/to/workspace/Build/验证/DexInvokeEvidence-20261006
```

`ORIGIN.md` 记录固定上游参考及权利，`VALIDATION.md` 记录本次验收，`THREAT_MODEL.md` 说明适用范围。CVP 申请资格仍为 **OPEN**。
