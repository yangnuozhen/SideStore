# 个人分支：Apple Watch 支持

本改造用于个人分支，不代表 SideStore、iLoader 或参考项目维护者背书。

## 安装与续签

- 可导入 `Payload/Host.app/Watch/Companion.app` 形式的 iPhone + Watch companion IPA。
- 可导入 `Payload/WatchApp.app` 形式的纯 Watch-only IPA；顶层 Watch app 不会安装到 iPhone。
- Watch 扩展和 Watch app 分别申请 profile，并重写 `WKCompanionAppBundleIdentifier`、`WKAppBundleIdentifier` 等关系。
- Watch-only app 显示在“我的应用”中。使用“刷新”会从缓存的原始应用重新签名并向手表覆盖安装。
- 包含 Watch companion 的应用刷新时会重新安装 iPhone host 和 Watch app。
- 不自动卸载手表上的旧应用。安装失败不会尝试通过删除应用绕过错误，也不会将 Watch 记录的到期时间推进。
- 使用最早过期的 profile 作为整组应用的到期时间。
- 日常签名、安装与续签都在 iPhone 上完成，无须电脑参与。首次安装 SideStore、VPN 和导入 iPhone 配对文件仍按 SideStore 原有流程完成。

## 使用条件

1. SideStore 已登录 Apple 账户，VPN 与普通 iPhone 应用安装正常。
2. 使用 `idevice` 设备通信后端。设置中保留或导入该 iPhone 的 **lockdown pairing file**；只有 RemotePairing 文件不能用于此路径。即使普通安装使用 RemotePairing，Watch 路径仍可读取已导入的 lockdown 配对文件。
3. 仅有一块配对手表，且目标 iPhone、手表处于连接、解锁及允许开发安装的状态。
4. Apple 账户须实际获得应用所需 capability。profile 必须含 watchOS 平台和目标 Watch 标识；App Group 必须经 Apple 授权。
5. 保留 SideStore 的原始 IPA 缓存。Watch 刷新需要重新签名；不能仅向 iPhone 注入 profile。

多块配对手表会明确报错。初次安装会记录目标手表，后续签名/安装会核对目标；更换手表时应移除 SideStore 中的旧记录后重新导入，避免误装到另一块手表。

支持 unsigned IPA 中明确声明的 `ALTAppGroups`、`WatchRegionAppGroup`。不从应用二进制字符串猜测权限，也不声称能恢复所有已剥离的 entitlements。

对于 Watch 图中显式声明 HealthKit entitlement 或 HealthKit 隐私用途的 bundle，会请求 HealthKit capability，并检查返回 profile 确实授权；Apple 拒绝时停止签名，不伪造权限。

## GitHub CI

主仓库包含依赖补丁及新增传输源码，**不需要另行提交或发布子模块 fork**。子模块 HEAD 保持原来的固定版本；工作区显示子模块 modified 是补丁的预期结果。

将主仓库改动推送到自己的仓库后，在 Actions 手动运行 **Personal Watch Support Build**，选择包含改动的分支。它使用 GitHub 的 `xcode-27` runner 并选择 Xcode 27.2，先构建 Watch SideStore，再从固定源码构建 LiveContainer 并合包。它不发布 Release，也不需要 Apple 签名密钥或仓库写权限。

**最终安装包**：下载 `LiveContainer+SideStore-Watch-Experimental` artifact，解压后按原项目方式侧载其中的 **`LiveContainer+SideStore.ipa`**。只需安装这一个 IPA，不必另外安装独立 SideStore。`SideStore-Watch-Experimental` artifact 保留为独立版调试产物。

合包保留上游的 `SideStoreSupport.framework`、`LiveProcess.appex`、小组件和刷新快捷指令。安装时保留应用扩展，才能使用上游的后台刷新机制。账户、VPN、lockdown 配对文件仍在内置 SideStore 中按正常流程配置；合包不会预置这些私人数据。

合包脚本验证 SideStore 输入 IPA 与同一次构建生成的哈希记录一致，不下载上游现成 SideStore。LiveContainer 和 dylibify 固定版本记录在 `scripts/livecontainer/build-config.json`；dylibify 在 CI 从源码编译。完整构建来源同时放入 IPA 的 `WatchSupportBuild.plist` 和 artifact 内的 `.build-info.json`。

更新本改造版时继续使用此 workflow 生成的合包。LiveContainer 内置官方源的更新包不包含本分支的 Watch 改造。

也可以在 macOS 上执行：

```sh
git submodule update --init --recursive
python3 scripts/watch-support/prepare.py
python3 scripts/watch-support/verify.py --require-swift
make build fakesign ipa BUILD_CONFIG=Release
```

上述命令只构建独立 SideStore。合包的完整 macOS archive/packaging 命令见 `.github/workflows/watch.yml` 的 `livecontainer` job；需要其固定版本 LiveContainer、dylibify 源码和 SideStore 的构建记录。

直接从 Xcode 打开项目时，先运行一次 prepare.py。Makefile 的 build、build-tests、build-and-test 已自动执行该准备步骤。

依赖补丁固定于：

- SideSign `752d1ef602aa792a432ffa1e71646dc1ecf7363c`
- minimuxer `12be70dc2627307a16bfd2dc7a009080d5bec909`

准备脚本可重复运行；版本不符或存在冲突时会停止，不覆盖未知本地源码。更新依赖后须重新审查并移植补丁。

## 验证与实机范围

Windows 本地可检查补丁在干净固定版本上的可重现性，以及新增 Swift 的语法。没有本机 Xcode，尚未完成此分支的 Xcode 编译、Apple profile 请求或实机安装验证。

合包逻辑另有 13 项 Python 离线测试，覆盖目录布局、Mach-O 转换结果检查、widget 迁移、App Intents 模块重写、完整 CLI 打包流程、IPA 往返解包、哈希不匹配、路径越界等情况。测试使用合成 Mach-O 与模拟转换/签名调用，不代表 dylibify、ldid 或 LiveContainer 已在实机验证。

CI 中的 verify.py 会执行**直接提取自生产源码**的 Swift bundle-graph 与 sparse ZIP 测试，再用 Python 独立解码生成的传输流，核对 CRC、文件内容、UTF-8 名称、ZIP metadata 及终止标记。测试覆盖 iPhone-only、Watch companion、Watch-only、扩展平台继承，以及 watchOS 返回错误、未收到 DataComplete、符号链接等失败路径。它不替代 TLS、Apple 服务和设备实测。

实机至少检查：

- companion 的 iPhone 与 Watch 部分均安装、启动；纯 Watch-only 包只出现在 Watch。
- 刷新后 Watch profile 到期时间推进，既有应用数据保留，手表端仍能启动。
- 断开/锁定手表、关闭 VPN、切换目标设备、拒绝 capability 时明确失败，不显示成功。
- 普通 iPhone-only IPA 安装与 profile 注入刷新保持原有路径。
- 合包内能打开 SideStore，重启后 Watch 安装记录仍在；LiveContainer 自身刷新后内嵌改造版与数据保留；小组件/快捷指令能唤起内置刷新。

当前不支持 Watch 应用备份/恢复、停用/激活、Watch JIT、远程启动或符号链接形式的 Watch 包。界面隐藏相关选项，操作管线也会拒绝不适用的备份/停用操作。Watch-only 记录可手动移除；不会因为 iPhone LaunchServices 查不到它而被自动清理。

设备传输的同步 C FFI 放在专用串行队列；网络读写有超时，完成以 watchOS 的 `DataComplete` 为准。任务取消可以阻止下一步，但正在执行的同步传输仍可能在超时前结束。

## 来源与许可

- [参考实现](https://github.com/Rzbck/iloader/tree/feat/watch-companion-support-20260909)
- [架构与已验证范围](https://github.com/Rzbck/iloader-watch-companion)
- [isideload 实现锚点](https://github.com/Rzbck/isideload/tree/f7b9f3da570edd6824c29680545e710846d07df5)
- [LiveContainer 合包流程](https://github.com/LiveContainer/LiveContainer/blob/9d6ea09b05afa2c8fc537c372795a294db631311/.github/build_github.sh)
- [dylibify 固定源码](https://github.com/LiveContainer/dylibify/tree/5daf713df9fb07724510490c88aa8e00061be14a)
- 本机 `F:\Mopelab\iloader-watch` 的 2.4.1-watch.2 迁移实现提供 companion 与 App Group 处理参考。

参考项目已验证的范围不等于本分支已验证。Standalone Watch-only 是本分支新增路径，必须通过实机确认。

Sparse ZIP 与 companion 协议改编自 MIT 授权的 isideload。完整授权文本保存在 `scripts/watch-support/LICENSE-isideload`。SideStore 及其依赖保留各自原有授权。
