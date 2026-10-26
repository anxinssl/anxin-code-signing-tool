# 开发与构建

本项目使用 C#、.NET 10 和 WPF。客户安装 EXE 发行版无需安装开发 SDK。

## 对应源码

`v1.0.44` 标签保留固定发行版的完整源码树。Releases 中单独附带的
`Anxin-Code-Signing-Certificate-Tool-1.0.44-source.zip` 与 EXE 内的源码清单对应。
默认分支在该源码基础上更新了网页介绍和使用文档，未修改程序源码。

## 开发环境

要求 Windows x64、.NET SDK 10.0.302、Node.js 22+、PowerShell 7 和 Git。

```powershell
dotnet restore CodeSigner.sln --locked-mode
pwsh -NoProfile -File scripts/test-public-source.ps1
```

默认脚本只执行明确筛选的非签名检查，不执行真实签名、证书读取或生产窗口操作。
不要直接运行全解决方案测试。源码 ZIP 使用者先执行 `git init` 和 `git add .`，
供文件清单检查使用。

## 构建安装包

```powershell
pwsh -NoProfile -File scripts/setup-nsis.ps1
git add .
node scripts/source-snapshot.mjs
pwsh -NoProfile -File scripts/build-nsis.ps1
```

NSIS 来自固定版本的维护者构建，来源和哈希见
`release/metadata/nsis-toolchain.json`。构建工具放在忽略的 `.local` 目录中。

源码 ZIP 输出到 `artifacts/source/1.0.44/`，安装包输出到
`artifacts/nsis-build/1.0.44/`。安装包携带 `source-manifest.json`，
记录源码树、源码 ZIP 哈希及逐文件哈希。

源码快照与安装包必须配套生成和发布；源码发生变化后，需要重新生成快照及安装包。
产品源码与发布身份受校验脚本约束，不应绕过相关检查。

## 安装器验证

```powershell
pwsh -NoProfile -File scripts/build-nsis.ps1 -TestPackage -SkipPublish
pwsh -NoProfile -File scripts/test-nsis.ps1
```

该测试只操作隔离 QA 环境。`INSTALLER-QA-ONLY` 文件不能交付客户，
实际安装和真实证书签名需要独立验收。

历史安装器定义和相关第三方条款保留用于追溯，不是当前发布入口。
当前发行包不捆绑 SimplySign、Windows SDK 或 SignTool。

参阅 [AGENTS.md](../AGENTS.md)、[贡献说明](../CONTRIBUTING.md)及
[第三方声明](../THIRD-PARTY-NOTICES.md)。
