# Windows ICMP / BestTrace 验证记录

已在 **Windows Server 2022 VM、管理员权限** 下原生构建并运行实验 Mihomo、Wintun 和
官方 BestTrace 3.9.6.6。受控 IPv4 路径及内核 RR 修复已有通过证据，不能泛化为所有 Windows 环境通过。

**最新完整回归 [36913225840](https://github.com/hbyq/mihomo-icmp-trace/actions/runs/36913225840) 已完成：原生单测、0 ms、5 ms 全接口与物理接口限定放行均通过。**

默认防火墙诊断保留“中间跳缺失”的失败；公网基线不可用，保持不确定，未计为公网路径通过。

## 2026-10-02：真实公网多目标对照

[任务 36954184208](https://github.com/hbyq/mihomo-icmp-trace/actions/runs/36954184208)
已在 **Windows Server 2022 / 2025** 分别对 `1.1.1.1`、`8.8.8.8`、`9.9.9.9`、
`223.5.5.5` 运行关闭 TUN、开启 mixed trace、开启 gvisor trace，共 24 次实际 BestTrace。
使用同一份已验证内核，SHA256 为 `6b01bb11de95bd51c10b7decb6a0c2a2ebe9f8d7147371a035b149bcc2d37383`。
本轮没有启用夹具，也没有生成模拟回应。

**所有 24 次都实际完成 32 跳，但全部为 `*`；公网验收仍是不确定。**
GUI 原生下拉框实际选中并读回 32，`tracert` 同样探测 32 跳，Windows Ping API
补测 TTL 64 / 128。因此结果不能归因于仅探测三跳、最大跳数过小或单一目标 IP。

| Windows | 目标 | 关闭 TUN | mixed TUN | gvisor TUN |
| --- | --- | --- | --- | --- |
| 2022 | 1.1.1.1 | [原图](evidence/windows/public-comparison/windows-2022/1_1_1_1/off.png) | [原图](evidence/windows/public-comparison/windows-2022/1_1_1_1/mixed.png) | [原图](evidence/windows/public-comparison/windows-2022/1_1_1_1/gvisor.png) |
| 2022 | 8.8.8.8 | [原图](evidence/windows/public-comparison/windows-2022/8_8_8_8/off.png) | [原图](evidence/windows/public-comparison/windows-2022/8_8_8_8/mixed.png) | [原图](evidence/windows/public-comparison/windows-2022/8_8_8_8/gvisor.png) |
| 2022 | 9.9.9.9 | [原图](evidence/windows/public-comparison/windows-2022/9_9_9_9/off.png) | [原图](evidence/windows/public-comparison/windows-2022/9_9_9_9/mixed.png) | [原图](evidence/windows/public-comparison/windows-2022/9_9_9_9/gvisor.png) |
| 2022 | 223.5.5.5 | [原图](evidence/windows/public-comparison/windows-2022/223_5_5_5/off.png) | [原图](evidence/windows/public-comparison/windows-2022/223_5_5_5/mixed.png) | [原图](evidence/windows/public-comparison/windows-2022/223_5_5_5/gvisor.png) |
| 2025 | 1.1.1.1 | [原图](evidence/windows/public-comparison/windows-2025/1_1_1_1/off.png) | [原图](evidence/windows/public-comparison/windows-2025/1_1_1_1/mixed.png) | [原图](evidence/windows/public-comparison/windows-2025/1_1_1_1/gvisor.png) |
| 2025 | 8.8.8.8 | [原图](evidence/windows/public-comparison/windows-2025/8_8_8_8/off.png) | [原图](evidence/windows/public-comparison/windows-2025/8_8_8_8/mixed.png) | [原图](evidence/windows/public-comparison/windows-2025/8_8_8_8/gvisor.png) |
| 2025 | 9.9.9.9 | [原图](evidence/windows/public-comparison/windows-2025/9_9_9_9/off.png) | [原图](evidence/windows/public-comparison/windows-2025/9_9_9_9/mixed.png) | [原图](evidence/windows/public-comparison/windows-2025/9_9_9_9/gvisor.png) |
| 2025 | 223.5.5.5 | [原图](evidence/windows/public-comparison/windows-2025/223_5_5_5/off.png) | [原图](evidence/windows/public-comparison/windows-2025/223_5_5_5/mixed.png) | [原图](evidence/windows/public-comparison/windows-2025/223_5_5_5/gvisor.png) |

截图保留实际窗口可见区域，通常显示前约 10 行；每次完整 32 行保存在同目录的
`off-rows.tsv` / `mixed-rows.tsv` / `gvisor-rows.tsv`。地图正常加载和地图报错两种情况
都出现全 `*`，地图显示不能解释本轮 ICMP 无回应。
[结构化结果与原图校验值](evidence/windows/public-comparison/validation.json) 可独立核对。

独立解析每次 Pktmon 捕获，均观察到 **204 个物理出口 Echo**，TTL 覆盖 **1–32、64、128**，
合计 4896 个；未观察到终点 Echo Reply，也没有引用目标的 ICMP 3 / 11 / 12 错误回应。
16 个 TUN 场景都确认目标走 Wintun，并出现 DIRECT trace handler 日志，没有 setup/send failure。
这证明公网探测经过内核且保留了逐跳 TTL；真实公网回包恢复仍未获验证。

8 个 Windows/目标组合的 **TCP 443 和 53 均成功连接**，默认规则和显式放行后高 TTL ping
均超时。全部对照使用一致的临时物理接口 ICMPv4 0 / 3 / 11 / 12 入站放行规则，测试后
都已删除；没有关闭防火墙或修改默认策略。不能把本轮无回应归因于某一个具体上游设备，
也没有证据要求继续修改内核或 BestTrace 来解决此公网基线限制。

GitHub 托管 Windows 使用 Azure；[默认出站访问](https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/default-outbound-access)
存在 ICMP 限制，但当前 runner 的具体出口类型未公开，guest `Get-NetNat` 为空也不能排除云侧 NAT。
[StandardV2 NAT](https://learn.microsoft.com/en-us/azure/nat-gateway/nat-gateway-resource) 支持 Echo，
仍不支持其他 ICMP 消息，不能用它的终点 ping 证明 Time Exceeded 可用。
下一次公网验收需要换到能收到中间路由 ICMP 错误的真实 Windows 出口，例如具备合适公共 IP
和网络规则的 Windows VM，先确认关闭 TUN 时有可用逐跳基线，再比较开启 TUN 后的结果。
workflow job 成功只表示证据收集完成；8 个比较结果均保留 `inconclusive`，没有转成 `pass`。

### 原三跳记录的含义

`192.0.2.1 → 192.0.2.2 → 203.0.113.77` 使用 RFC 5737 文档保留地址，并非实际内网路由器。
在同一次 36913225840 的物理接口限定放行受控测试中，关闭 TUN 也得到同样三跳：
[关闭 TUN 原图](evidence/windows/controlled-comparison/off.png) ·
[开启 mixed 原图](evidence/windows/controlled-comparison/mixed.png) ·
[开启 gvisor 原图](evidence/windows/controlled-comparison/gvisor.png)。
这条路径是测试器规定的拓扑，不能从其长度推断真实公网路线。
真实路径可能因 anycast 很近，也可能有许多不回应 ICMP 的路由器；是否有效要看同一出口、
同一目标的 TUN 关闭/开启对照，而不是设定一个必须出现的公网跳数。

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
