# 安信代码签名证书工具 1.0.44

Copyright (C) 2026 安徽斯百德信息技术有限公司

Windows 10/11 x64 桌面代码签名工具，使用 C#、.NET 10 和 WPF。
第一方代码采用 [GPLv3，仅限第 3 版](LICENSE)，第三方声明见
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。

## 使用

运行正式发布的 `Anxin-Code-Signing-Certificate-Tool-1.0.44-win-x64-Setup.exe`。
安装包自带 .NET 运行时，客户不需要安装开发 SDK。
新安装器使用 NSIS，不再使用 WiX 构建 MSI。

**从旧 MSI 版本迁移：**先关闭工具，在 Windows 设置中卸载旧版安信证书签名工具，
再运行新版 EXE 安装包。保留 SimplySign、证书、原文件和输出文件。
新版检测到旧 MSI 时会停止安装并说明步骤，不会自动卸载已验证版本。
安装到受保护的 `Program Files\AnxinCodeSigner`，不支持自行移动程序目录。

云证书先登录对应客户端；硬件 UKey 先插入设备并确认对应驱动已识别。
打开工具，刷新并选中有效证书，导入文件，
选择签名模式及独立输出目录，然后开始签名。详见[使用教程](docs/user-guide.md)。
底部“安信官网”打开代码签名证书页面；“联系技术支持”弹出企微二维码。

## 开发与验证

要求 Windows x64、.NET SDK 10.0.302、Node.js 22+、PowerShell 7 和 Git。

```powershell
dotnet restore CodeSigner.sln --locked-mode
pwsh -NoProfile -File scripts/test-public-source.ps1
```

默认脚本只运行明确筛选的非签名检查，不执行真实签名、证书读取或生产窗口操作。
不要直接运行全解决方案测试。ZIP 源码使用者先执行 `git init` 和 `git add .`，
供文件清单检查使用。

## 构建

```powershell
pwsh -NoProfile -File scripts/setup-nsis.ps1
git add .
node scripts/source-snapshot.mjs
pwsh -NoProfile -File scripts/build-nsis.ps1
```

NSIS 来自固定版本的 electron-userland 维护者构建，下载地址、源版本和哈希见
`release/metadata/nsis-toolchain.json`。构建工具仅放在忽略的 `.local` 目录中。
源码 ZIP 输出到 `artifacts/source/1.0.44/`，安装包到 `artifacts/nsis-build/1.0.44/`。
安装包携带 `source-manifest.json`，记录源码树、源码 ZIP 哈希及逐文件哈希。
必须同时发布这两个配套文件；改动源码后须重新生成源码快照及安装包。

```powershell
# 只操作隔离的每用户 QA 目录，不替换生产安装
pwsh -NoProfile -File scripts/build-nsis.ps1 -TestPackage -SkipPublish
pwsh -NoProfile -File scripts/test-nsis.ps1
```

`INSTALLER-QA-ONLY` 文件不能交付客户。管理员安装、旧 MSI 迁移、
Windows 设置卸载及真实签名仍需人工验收。

## 修改边界

签名引擎、证书读取、时间戳、Worker、文件处理及批量签名算法保持原固定版源码。
1.0.44 在 1.0.43 基础上仅移除文件队列中的公司名称装饰水印。
证书筛选、私钥调用、签名执行和签名前置校验保持 1.0.42 的行为。
不根据是否安装 SafeNet 放行，不探测真实私钥或在刷新时试签。
既有维护提示仅替换字符串，校验脚本逆向恢复
这些固定替换后验证原始方法所在文件的哈希。

历史 MSI 定义和工具仅保留用于追溯，不在当前解决方案或发布入口中构建。
不要使用旧的 `build-codesigner-signing-diagnostics-110.mjs` 发布本版本。
历史 WiX 条款记录不代表历史使用义务已经解决。
本项目不捆绑 SimplySign、Windows SDK 或 SignTool。

参见[贡献说明](CONTRIBUTING.md)、[安全说明](SECURITY.md)。
