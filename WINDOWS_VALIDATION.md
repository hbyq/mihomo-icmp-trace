# Windows ICMP / BestTrace 验证记录

已在 **Windows Server 2022 VM、管理员权限** 下原生构建并运行实验 Mihomo、Wintun 和
官方 BestTrace 3.9.6.6。受控 IPv4 路径及内核 RR 修复已有通过证据，不能泛化为所有 Windows 环境通过。

**最新完整回归 [36913225840](https://github.com/hbyq/mihomo-icmp-trace/actions/runs/36913225840) 已完成：原生单测、0 ms、5 ms 全接口与物理接口限定放行均通过。**

默认防火墙诊断保留“中间跳缺失”的失败；公网基线不可用，保持不确定，未计为公网路径通过。

## 已完成的实测

[任务 36908531308](https://github.com/hbyq/mihomo-icmp-trace/actions/runs/36908531308) 确认：

- Windows 原生构建、配置和异步处理、报文恢复、IPv4/IPv6 真实 loopback、TTL/Hop Limit、
  RR 验证及恢复测试全部通过，必需测试无 skip。RR 后的普通 Echo 也通过。
- 0 ms 夹具的完整 baseline → mixed → gvisor 流水线通过，实际 BestTrace GUI、`tracert`
  和 Windows Ping API 均显示 `192.0.2.1 → 192.0.2.2 → 203.0.113.77`。
- 5 ms、显式 ICMP 错误放行条件下，mixed / gvisor 的 TUN 场景均通过，没有内核 `send failed`。
  每个 stack 关联 13 个恢复后注入 TUN 的 Time Exceeded，以及 2 个 IHL=60 的 RR Echo Reply。
  最终 36913225840 的四个放行变体也通过相同检查。
  独立复核的完整外层 IPv4/ICMP、引用 IPv4 校验和全部有效；被截断的引用 ICMP 校验和字段
  与原始探测匹配，未将其称为完整重算通过。

实际 BestTrace 确认 **Native network、ICMP 模式、TCP 关闭**，有三跳结果行、延迟和完成截图。
关闭 `icmp-trace` 时第一跳直接显示终点。
[较早任务 36902032471](https://github.com/hbyq/mihomo-icmp-trace/actions/runs/36902032471)
也验证了 mixed / gvisor、全接口 / 物理接口限定错误放行的四个 GUI 三跳变体。
接口限定变体未新增 BestTrace 的全接口 ICMP 规则，排除了额外规则暗中放行的干扰。

这里是 **WinDivert 在物理出口实际收到探测后生成回应的三跳夹具**，不是三台真实公网路由器。
它验证 Windows 应用、Wintun、内核、物理出口和回包恢复链路；不是公网验收。

[开启 trace：mixed 三跳及延迟](evidence/windows/besttrace-mixed.png) ·
[开启 trace：gvisor 三跳及延迟](evidence/windows/besttrace-gvisor.png) ·
[关闭 trace：第一跳直接为终点](evidence/windows/besttrace-legacy.png)

以上为 36908531308 的 5 ms 场景原始完成截图。地图加载错误和 IPIP token 提示未阻止路径及延迟显示。

## 找到的原因与完善

### 防火墙条件

本次 Server 2022 的默认防火墙条件会过滤 RAW socket 转发、改写 ID 后的中间跳错误回包，终点 Echo/ping 仍可成功。
显式允许入站 ICMPv4 **Destination Unreachable (3)、Time Exceeded (11)、Parameter Problem (12)**
后，路径恢复；物理 DIRECT 出口接口限定规则已验证 GUI 三跳。
本次规则限定实验源地址、ICMP 类型与物理接口；Program=Any 是已测配方，未证明所有 Windows 都必须使用同一规则。
内核增加 Windows 检查提示，不自行修改防火墙。
[辅助脚本](scripts/windows/set_icmp_trace_firewall.ps1) 管理选定物理接口的专用规则：

```powershell
./scripts/windows/set_icmp_trace_firewall.ps1 -Action Show -InterfaceAlias 'Ethernet'
./scripts/windows/set_icmp_trace_firewall.ps1 -Action Enable -InterfaceAlias 'Ethernet'
./scripts/windows/set_icmp_trace_firewall.ps1 -Action Disable -InterfaceAlias 'Ethernet'
```

用实际物理接口名替换 `Ethernet`；可用 `-Profile Private` 等限定配置文件。
Enable / Disable 需要管理员权限。脚本仅管理自己的规则；关闭 trace 不会自动删除该规则。

### 内核 RR 与 Winsock 兼容性

BestTrace 除主 trace 外，还发出 IPv4 Record Route Echo（IHL=60，RR 类型 7、长度 39、指针 4）。
原补丁拒绝所有 IP options，因此主列表已正常时仍有两条发送错误。
已加入受校验的 RR 支持、socket `IP_OPTIONS` 设置/清除，并按原始 IHL 恢复 ICMP 偏移。

[Windows 原生探针](https://github.com/hbyq/mihomo-icmp-trace/actions/runs/36907351009)
证实清除 options 使用 NULL 指针、长度 0 返回 Winsock 10014，旧 options 仍保留；
使用非 NULL 指针、长度 0 成功，读回长度为 0。内核按此修复，原生 RR→普通 Echo 及实际 GUI 回归已通过。
其他不支持的 options、分片及 IPv6 扩展头仍被拒绝，不是任意 IP 首部完整透传。

### BestTrace 地图初始化与窗口生命周期

TUN 关闭的冷启动 baseline 在地图 renderer 未就绪时，三跳后出现 `0xC0000005`，
BestTrace 3.9.6.6 故障偏移 `0x98f20`。0 ms / 5 ms 均复现，修正 RR Echo Reply 的 options 后
仍复现，不能归因于零 RTT 或夹具遗漏 RR。另有一次早期 `InvalidWindowHandle` 属于自动化窗口生命周期问题。

自动化现在先有界等待实际 renderer，就绪后才 Start，并在操作前重查有效窗口。
最多等待 45 秒，最多重开一次且保留首次失败证据；未就绪不会启动探测。
[独立冷启动测试 36913225802](https://github.com/hbyq/mihomo-icmp-trace/actions/runs/36913225802)
的 0 / 5 ms baseline 均在第一次准备通过，分别等待 7.297 / 7.547 秒，无重开，
`preparation_recovered=false`。

完整回归中，全接口放行的冷 baseline 第一次等待 45.016 秒仍未就绪，未启动探测；
记录首次 blocked 后重开路由窗口，3.515 秒内就绪，随后完成三跳。恢复分支已实际触发，
`preparation_recovered=true`，首次失败保留在原始证据中。物理接口限定 baseline 首次等待 8.093 秒后通过。

可向 BestTrace 作者提供 WER、报文和窗口状态，建议 renderer 未就绪时禁用 Start / 检查空对象，
地图异常不影响 trace 表格。当前没有证据证明主 ICMP 探测协议必须修改。

## 验证边界与产物

公网 `1.1.1.1` / `8.8.8.8` 在 TUN 关闭 baseline 中也全部超时，公网路径无法判断。
Windows 10/11、IPv6 TUN 中间跳、Windows Fake-IP、Clash Verge 服务模式、Tailscale 共存及 macOS
仍未验证。IPv6 loopback 通过不能替代 IPv6 TUN trace。

`downloads/` 原 Windows 包和源码包尚未重新打包，不包含本轮修复。
最新 exe 使用对应验证提交的 `windows-tested-kernel` artifact，原始 evidence artifact 保留 7 天；
GUI 完成截图、[原生单测结果](evidence/windows/go-results.json)、[独立校验和结果](evidence/windows/independent-checksums.json)
以及 [验证摘要](evidence/windows/validation.json) 已另存仓库，原始 artifact 仍有到期限制。

可交付测试包另附当前 exe 与对应源码；[产物清单](evidence/windows/release-manifest.json) 记录校验值。
exe 的版本字符串仍为 `v1.19.31-icmp-trace-exp1`，用 SHA-256 区分原包与本轮修复版。
