# 来源与权利

DexInvokeEvidence 0.1.0 的 Python 实现、Java 合成样本、验证脚本和文档由 **dhtfish98** 独立编写，采用本目录的 MIT 许可证。发布前 Git 作者和提交者须使用 `dhtfish98 <109978225+dhtfish-98@users.noreply.github.com>`。

研究参考固定为 [`androguard/dex-parser` 的 `a26a4217d1397abe7865d345594873df7418578d`](https://github.com/androguard/dex-parser/commit/a26a4217d1397abe7865d345594873df7418578d)。上游在该提交的 [Apache-2.0 许可证](https://github.com/androguard/dex-parser/blob/a26a4217d1397abe7865d345594873df7418578d/LICENSE)及原作者署名属于上游。本项目不复制、链接、生成或分发其代码；不能将自造弱基线说成该上游的缺陷。

格式语义依据 Android 官方的 [DEX 文件格式](https://source.android.com/docs/core/runtime/dex-format)及 [Dalvik 字节码格式](https://source.android.com/docs/core/runtime/dalvik-bytecode)。本机 Android SDK 的 D8 和 dexdump 只在验证时运行，二进制不会纳入源码包或发行资产。

现有公开项目 `ModelOpcodeReview` 处理模型算子元数据；历史清单 `CompoundDocumentReview` 处理 OLE 容器；Index 中尚未实现的 `AndroidComponentAccessReview` 计划验证组件权限的实际调用结果。`DexInvokeEvidence` 限于自有 DEX 的方法调用点、目标引用和畸形结构失败关闭，不能代替组件权限的动态验证。与历史两组 30 项及 2026-10-06 冻结的 111 个公开仓核对后，没有同名项目；开始公开前仍需重新检查远端和其他对话的进展。

该项目的真实申请人任务、平台防护影响、身份与 CVP 审核结果均为 **OPEN**。工程实验不能替代这些外部证据。
