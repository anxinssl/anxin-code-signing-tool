# Contributing

The project is licensed under [GPL-3.0-only](LICENSE.md).
Do not submit confidential files or certificate material.

1. Use Windows x64, the SDK in `global.json`, Node.js 22+ and PowerShell 7.
2. Restore using the locked dependencies in [README.md](README.md).
3. Keep changes narrow. Do not change the frozen signing core without separate approval.
4. Run `pwsh -NoProfile -File scripts/test-public-source.ps1`.
5. Explain the change, selected tests, limitations and manual checks in the pull request.

Real certificates, provider login, signing, installer UI and desktop automation are
not part of the default test workflow. They require a separately agreed test scope.
Never upload test logs without inspecting them for sensitive data.

New releases need an explicit version decision, updated metadata and full verification.
Do not reseal the frozen internal 1.0.40 installer or mislabel changed binaries as that artifact.
