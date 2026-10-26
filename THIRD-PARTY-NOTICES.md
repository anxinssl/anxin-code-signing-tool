# Third-Party Materials

First-party source uses GPL-3.0-only; see [LICENSE.md](LICENSE.md).
Third-party materials keep their respective terms.

| Material | Use | License / terms |
| --- | --- | --- |
| Lucide 0.468.0 | Adapted WPF command icons | ISC; original notice in `licenses/lucide-license.txt` |
| .NET runtime 10.0.10 | Self-contained App and Worker | MIT and bundled third-party notices in `licenses/` |
| Windows Desktop runtime 10.0.10 | WPF runtime | MIT notice in `licenses/dotnet-windowsdesktop-license.txt` |
| NSIS 3.12 maintainer build | Current EXE installer | zlib/libpng and component terms, including the NSIS LZMA linking exception; `licenses/nsis-license.txt` |
| WiX Toolset SDK 6.0.2 | Build tool only, not installed as product payload | Source uses MS-RL; official precompiled distribution includes separate OSMF terms |
| Microsoft.NET.Test.Sdk / xUnit | Development and test dependencies only | NuGet package license metadata recorded in `licenses/nuget-inventory.json` |

WiX is historical tooling, not used by the 1.0.41 build. Its package includes `requireLicenseAcceptance=true` and the
[OSMF agreement](licenses/wix-osmf-eula.txt). Maintainers must review applicability
to their use and any existing maintenance arrangement. This repository does not
assert that fees have been paid, waive obligations, or accept an agreement for a company.

Lucide source commit, reference paths and hashes are recorded in
`src/CodeSigner.App/Assets/CommandIcons/SOURCE.json`. The copy icon has adjusted
coordinates; its provenance entry explicitly identifies it as an adaptation.

`scripts/build-third-party-notices.mjs` combines the unchanged Lucide and .NET
notices and NSIS notices into `THIRD-PARTY-NOTICES.txt`, a required EXE installer payload
verified by isolated installation tests. When updating runtime versions, review and replace
the corresponding notice texts and metadata, regenerate the combined notice,
and rerun the package contract tests.

NuGet dependencies are centrally versioned and locked. The inventory is a snapshot
of local package metadata, not a legal opinion or proof that all notices are exhaustive.
WiX and test tools are not bundled with the product.

SimplySign is installed separately by the customer. Its installer and documentation
are not redistributed in this source tree. Brand names, logos and the support QR
image are not covered by third-party code licenses. See `NOTICE` for trademark terms.

NSIS source: https://github.com/kichik/nsis
Pinned source commit and compiler binary hash: `release/metadata/nsis-toolchain.json`.
