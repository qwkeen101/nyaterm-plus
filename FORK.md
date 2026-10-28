# NyaTerm Plus 分支规则

这个仓库是 [nyakang/nyaterm](https://github.com/nyakang/nyaterm) 的个人改版。2026-10-28 整个重来：旧的 Tauri + React 版本连同历史全部删掉，从原项目 `v2.0.0`（Rust + GPUI 原生版，原项目提交 `1a449125a`）的代码开始，只有一个起始提交，没有原项目的历史。

## 跟进原项目

- `upstream` 只用来拉取，推送地址故意设成 `DISABLED`，不要改。
- 因为没有共同历史，**不能 `git merge upstream/main`**。要跟进原项目，先 `git fetch upstream`，再把 `v2.0.0` 之后的提交挑进来：`git cherry-pick <提交>` 或一段 `git cherry-pick A..B`（起点是上次跟到的那个原项目提交，记在下面）。冲突时两边都保留：原项目的修改要进来，下面「我们自己的改动」一个都不能丢。
- 上次跟到：原项目 `v2.0.0`（`1a449125a`）。

## 我们自己的改动（跟进原项目时必须保住）

- **改名为 NyaTerm Plus，能和原版同时装**：`crates/nyaterm-core/src/app_identity.rs` 里正式版 / 预览版两种身份都换成 Plus 自己的：名字「NyaTerm Plus」/「NyaTerm Plus Preview」、配置文件夹 `~/.nyaterm-plus` / `~/.nyaterm-plus-preview`（单实例锁也在里面，所以和原版互不抢）、桌面 id 和网址协议 `nyaterm-plus` / `nyaterm-plus-preview`（`activation/deep_link.rs` 认这两个协议）、标识符 `com.kang.nyaterm.plus`。
  - 打包脚本 `scripts/release/package_native.py` 的 `STABLE_IDENTITY` / `PREVIEW_IDENTITY` 跟着换（安装目录 `%LOCALAPPDATA%\Programs\NyaTerm Plus`、注册表 `Software\NyaTermPlus`、卸载项、开始菜单都不和原版重名），`crates/nyaterm-app/build.rs` 的 exe 属性 `ProductName` / `FileDescription` 改成 NyaTerm Plus，`verify_native_package.py` 的检查跟着改。
  - 测试里的期望值跟着改：`runtime.rs`、`native_menu/tests.rs`、`scripts/tests/test_package_native.py`、`scripts/tests/test_verify_native_package.py`。
  - exe 文件名还是 `NyaTerm.exe`（装在不同目录，不冲突；改它要动的地方太多）。
  - **MSI 没改**：`scripts/release/windows_msi.py` 还是原项目的名字和 `UpgradeCode`，装了会顶掉原版。所以只出 `setup.exe` 和免安装 zip，开发版用带 `-dev.N` 的版本号，打包脚本见到预发布版本号就不出 MSI。要出 MSI 得先换掉这些。
- **关闭自动更新**：原项目的更新服务器只有原版 NyaTerm，更新了会把 Plus 换成原版。`crates/nyaterm-desktop/src/http/update.rs` 的 `PLUS_UPDATES_ENABLED = false`，检查更新直接报「去 GitHub Releases 下载」，启动时的静默检查也不联网。
- **GitHub 自动出安装包**：`.github/workflows/plus-build.yml`。推 `main` 就编 Windows 64 位，发到 Releases 里固定的 `plus-dev`（预发布），每次覆盖成最新，标题「NyaTerm Plus 开发版 N」（N = 这个 workflow 的运行号），文件名 `NyaTerm-Plus_2.0.0-dev.N_windows_x64-setup.exe` / `…_portable.zip`。连推几次只编最后那次。原项目自带的 `rust.yml`（检查 + 测试）、`docs.yml` 推 `main` 时也会跑，公开仓库不花钱。

以后新加了功能，也要补到这个列表里。

## 开发方式

- 在这台服务器上只写代码，**不要编译**（只有 2G 内存，GPUI 版是 50 多万行 Rust）。只装了 `rustfmt` 用来排版（`~/.cargo/bin/rustfmt --edition 2024`），编译和测试全靠 GitHub。
- 提交用 `qwkeen101` 和 GitHub 的 noreply 邮箱，不要把用户的 Gmail 写进公开历史。
- **不要 `git push --tags`**：会触发原项目的发布流程。
- 这是公开仓库：测试里只用 `203.0.113.x` 这类文档专用地址，不要写用户服务器的真实 IP。
