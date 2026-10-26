# 安信代码签名证书工具

<img src="src/CodeSigner.App/Assets/CodeSigner.png" alt="安信 SSL 证书" width="64" height="64">

适用于 Windows 的免费、开源中文图形化代码签名工具，用于为 EXE、DLL、MSI 等文件添加代码签名和时间戳，适合软件开发、测试及发布人员使用。

工具基于 Windows 原生证书与代码签名机制，通过兼容的证书客户端或硬件驱动完成签名。用户无需导出私钥或手动编写签名命令，即可在界面中完成证书选择、文件导入和签名操作。

**[下载安装包](https://github.com/anxinssl/anxin-code-signing-tool/releases/latest)** · **[使用教程](docs/user-guide.md)** · **[安信官网](https://www.anxinssl.com/)** · **[反馈问题](https://github.com/anxinssl/anxin-code-signing-tool/issues)**

## 主要功能

- **中文操作界面**：常用按钮配有文字说明，可查看证书信息、文件队列、处理进度和结果。
- **云证书与硬件 UKey**：云证书配合 SimplySign Desktop 等兼容客户端使用；DigiCert、Sectigo、GlobalSign 等 CA 的硬件 UKey 代码签名证书，需配合 SafeNet 等设备对应驱动，并满足本工具的证书及私钥调用要求。
- **单签与双签**：提供 SHA-256 单签及符合条件时的 SHA-1 + SHA-256 双签，并提示文件可用的签名方式。
- **批量处理**：支持添加多个文件或从文件夹导入待签名文件，按队列执行签名。
- **时间戳与输出管理**：支持配置时间戳服务，并将签名结果保存到用户选择的独立输出目录。
- **日志与诊断**：提供错误提示、日志及诊断导出入口，便于定位使用中的问题。

## 常用文件的签名方式

| 文件类型 | 签名方式 | 使用条件 |
| --- | --- | --- |
| EXE、DLL、OCX 等真实 PE 文件 | 单签或双签 | 双签需文件支持，并选择合适的辅助证书。 |
| MSI、CAB 文件 | 单签 | 在本工具中不使用双签。 |

文件后缀不是唯一判断依据；其他格式及具体可用模式，以工具检测结果为准。

## 下载与安装

适用系统：**Windows 10/11 x64**。

在 [Releases 页面](https://github.com/anxinssl/anxin-code-signing-tool/releases/latest)下载并运行 **EXE 安装包**，按照提示完成安装。安装包自带 .NET 运行时，无需额外安装 .NET SDK。

普通用户选择 EXE 安装包；对应源码 ZIP 用于查看源码及自行构建。

## 开始签名

准备证书：

- **云证书用户**：安装并登录对应客户端。例如，Certum 云证书配合 SimplySign Desktop 使用。
- **硬件 UKey 用户**：安装 SafeNet 等设备对应驱动，插入 UKey，确认客户端能够识别设备和证书。此类用户无需额外安装 SimplySign。

操作步骤：

1. **刷新证书**：打开工具，点击“刷新证书”，看到有效证书后选择主证书。
2. **添加文件**：点击“添加文件”或“添加文件夹”，检查待签名文件队列。
3. **选择模式**：通常使用单签；需要双签时，确认文件支持双签并选择符合要求的辅助证书。
4. **选择输出位置**：使用有写入权限的独立文件夹，输出目录不能与原文件位置相同。
5. **开始签名**：点击“签名”，等待队列处理完成，期间保持客户端会话或 UKey 连接。
6. **获取结果**：查看各文件的处理结果，打开输出目录获取签名后的文件。

## 使用注意事项

- 需自行准备有效的代码签名证书及对应客户端或驱动，工具不附带证书。
- 证书需具备代码签名用途、关联私钥，并能通过对应客户端或驱动完成调用；不同云服务、UKey 型号和驱动版本的兼容性以实际环境为准。
- 添加时间戳需要网络可用。
- 遇到保存失败或权限提示时，请更换可写的独立输出目录后重试；桌面和 C 盘并非一律不可用。

## 开源与技术支持

本工具使用 **C#、.NET 10 和 WPF** 开发，第一方代码采用 **GNU GPL 第 3 版，仅限第 3 版（GPL-3.0-only）**。许可证全文、版权及第三方说明见 [LICENSE](LICENSE)、[NOTICE](NOTICE) 和 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。

欢迎通过 [Issues](https://github.com/anxinssl/anxin-code-signing-tool/issues) 反馈问题和建议，提供软件版本、系统版本、证书使用方式及错误信息，提交前请对诊断资料脱敏。

证书选购与签名使用咨询：[安信代码签名证书](https://www.anxinssl.com/code-signing-certificate/)。也可通过软件内“联系技术支持”按钮获取帮助。

开发者请参阅[开发与构建说明](docs/development.md)、[贡献说明](CONTRIBUTING.md)和[安全说明](SECURITY.md)。
