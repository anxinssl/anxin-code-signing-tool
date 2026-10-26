# 1.0.40 公开源码整理记录

> 历史记录：以下描述的是 2026-09-23 的 1.0.40 候选状态。
> 当前 1.0.41 已获准采用 GPLv3，使用 NSIS；请以根目录 README 和 LICENSE 为准。

日期：2026-09-23。版本保持 1.0.40 / 1.0.40.0。

## 来源与边界

本目录从完整的 1.0.40 工作树整理，包含此前尚未进入历史提交的必要源码、
运行资源和依赖锁文件。没有复制旧 Git 历史，不会以旧 HEAD 的 1.0.26 冒充当前版本。
未改动原工作目录或原交付 MSI。

原交付 MSI 的 SHA256：
`C2C0F4421033D928CF9286BAF29DA93181EA185E7F42F7E3D445BDDCC794A491`。
原源码发布指纹：
`sha256:6bde8269958b9fca2b0bdbedcb14156e075b69089cd2999e5c3d77b548ab3fff`。
这两个值只标识原内部交付，不标识本目录重新构建的文件。

签名核心、Windows 层、Worker 和全部 ViewModel 保持冻结。
公开整理只改动系统程序启动路径及文档、测试可移植性、构建检查和第三方声明打包。
冻结清单以规范化 LF 后的 SHA256 比较，兼容 Git 换行处理。

## 未公开的内容

- 旧 Git 历史、开发机证据目录、运行日志、证书、凭据、构建产物及本地 SDK。
- 旧文档全集、客户截图教程、原始设计素材、第三方客户端截图和第三方安装文件。
- 以下历史审计测试依赖作者机器的已封存产物，未作为可移植测试公开：
  `CertumLiveLauncherTests`、`InteractiveSelfTestLauncherTests`、
  `StoreRetainedSha1DiagnosticLauncherTests`、`SealedArtifactManifestVerifierTests`，
  以及 `Todo7VerifierFixTests.PublishedEvidenceBundleContainsOnlyHashBoundSanitizedDerivatives`。
- 历史队列 UI QA 路由、修复状态审计脚本及其两项契约文件，
  历史诊断基线审计脚本、机器相关的生命周期 MSI 构建脚本。

这些移除只针对历史证据检查，不表示原有签名测试全部完成或全部迁移。
保留其余产品测试，但默认入口仅执行已检查的非签名范围。
UI 布局回归素材迁移到 `tests/fixtures/ui-baseline`，
只保留必要属性、视口矩阵、源码行和三份空界面 XAML，不保留机器目录和 Git 状态。

## 发布前仍须确认

- 权利人批准开源、许可证及署名，确认品牌和客服二维码可公开分发。
- 核对 WiX 官方二进制的 OSMF 条款适用情况。
- 配置 GitHub 私密漏洞报告渠道、分支保护和维护人员。
- 不上传内部 MSI 冒充本源码构建，不把自动检查替代为真实签名验收。

本地整理和检查不等于已经向 GitHub 发布。
