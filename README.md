# Mihomo 1.19.31 ICMP trace 实验补丁

测试目标：Clash Verge Rev 2.5.6 / Mihomo 1.19.31 / Windows x64。
这是独立实验内核，不是 Mihomo 官方发布版。Windows 二进制已交叉编译；
Windows 真机、Verge 服务模式和 Tailscale 同时运行时的验收尚未完成。

## 下载

- [Windows x64 测试包](downloads/mihomo-windows-amd64-icmp-trace-exp1.zip)
- [完整对应源码](downloads/mihomo-icmp-trace-exp1-source.zip)
- [SHA-256 校验值](SHA256SUMS.txt)
- [发布检查说明](SECURITY_REVIEW.md)
- [测试结果摘要](TEST_RESULTS.json)

在 GitHub 文件页面选择下载原始文件，或使用说明末尾的直链。
测试包内含实验内核、说明、版本清单与许可证。

## 改造内容

- 增加默认关闭的 `tun.icmp-trace` 开关，原有行为在关闭时保持不变。
- 使用不绑定远端地址的原始 ICMP socket，允许接收中间路由器回包。
- 每个请求保留 TTL / IPv6 Hop Limit，设置与发送串行，避免并发探测串包。
- 识别 Echo Reply、Time Exceeded、Destination Unreachable、Packet Too Big /
  Fragmentation Needed 和 Parameter Problem，并根据错误中引用的原始探测匹配请求。
- 为在途请求分配独立 ID，恢复应用的 ID、序号、源/目标地址及校验和。
- Fake-IP 通过已有映射找回域名，使用 direct-nameserver（未设置时用默认解析器）
  获取同地址族的真实目标，保留中间跳的真实来源地址。
- 域名解析、socket 初始化和发送在后台处理，不阻塞 TUN 收包循环。
- 初始化失败时关闭探测会话并记录日志，不回退为伪造的成功响应。
- 支持配置重载；拒绝同时启用 `icmp-trace` 和 `disable-icmp-forwarding`。

本次修复针对 **ICMP Echo 型 ping / Windows tracert / ICMP 模式的 MTR**。
它仍经本机 DIRECT 出口发送，不通过普通代理节点转发 ICMP，也不是“不接管 ICMP”。
macOS 默认 UDP traceroute、TCP traceroute、IPv6 扩展头、IPv4 IP options、
分片的原始探测以及其他 ICMP 请求类型不在这个实验版本的支持范围。
macOS 尚未做实际运行验证。
本版本重点保留 TTL/Hop Limit，并未完整透传所有 IP 首部属性（例如 IPv4 DF/TOS）；
不要把它当作已经验证过的完整 PMTU/任意原始 IP 数据包转发实现。

## 已完成验证

- Windows x64 完整内核交叉编译成功，包含 `with_gvisor`；可执行文件为 PE32+ x86-64。
- Linux 下原有 ping 测试和新增转发测试通过 race 检测；包含并发请求、真实 IPv4/IPv6
  loopback 回应、独立 raw socket 抓取到的 TTL=1/2/7/31，以及截断报文和错误匹配检查。
- 5 秒模糊测试完成 178149 次输入，没有发现崩溃。
- 配置转换、冲突检查、配置重载和异步 DNS/取消/队列上限测试通过。
- 对公网发送一次 TTL=1 的真实探测，收到中间路由器的 Time Exceeded 回应。
- 完整 Mihomo 在三个隔离 Linux 网络命名空间中通过 16 项端到端测试：
  mixed / gvisor × IPv4 / IPv6 × 真实 IP / Fake-IP 域名 × 第一跳 / 终点。
  最初 IPv6 测试失败也出现在关闭 TUN 的基线中；等待邻居发现完成后，基线与全部测试通过。
- 尚未完成 Windows 真机、Windows 防火墙、Clash Verge 服务模式与 Tailscale 共存验收。
  以上结果证明实验实现可工作，不能替代 Windows 实机测试。

## 在 Windows 上试用

1. 先保存现有内核版本、运行配置，以及 TUN 关闭时相同目标的 trace 结果。
2. 查看正在运行的内核文件路径：

   ```powershell
   Get-CimInstance Win32_Process |
     Where-Object { $_.Name -match 'mihomo' } |
     Select-Object Name, ExecutablePath
   ```

3. 停止 Clash Verge 及其正在运行的 Mihomo 服务进程。备份上一步确认的原内核文件。
   将实验 exe 复制到相同位置，使用原内核文件名；不要在进程仍运行时覆盖。
   如果安装目录需要管理员权限，使用管理员权限完成文件替换。
4. 启动 Verge，确认内核版本包含 `v1.19.31-icmp-trace-exp1`。
5. 在扩展配置中合并以下内容，保留现有 TUN 其他设置。实验阶段先用 `mixed`：

   ```yaml
   tun:
     icmp-trace: true
     disable-icmp-forwarding: false
   ```

6. 检查 Verge 的最终运行配置确实包含 `icmp-trace: true`。它是此补丁新增的字段，
   官方内核不提供该功能；只把这一行加到官方版不能完成修复。
7. 使用独立 Tailscale 客户端时，保留现有 `100.64.0.0/10` 和
   `fd7a:115c:a1e0::/48` 路由排除；在最终运行配置中确认没有被 GUI 覆盖。

验证时使用自己的公网目标和域名，例如：

```powershell
tracert -4 -d 1.1.1.1
tracert -4 -d www.wikipedia.org
ping -4 -n 4 1.1.1.1
# 仅在本机具有可用 IPv6 出口时测试：
tracert -6 -d 2606:4700:4700::1111
```

检查要点：

- TUN 开启后应能收到中间跳，已知会回应的路径不再固定一跳到终点。
- 与 TUN 关闭时对同一个真实 IP 的结果对照。路由器不回应 ICMP 时出现 `*` 是正常情况，
  不能要求所有网络都返回每一跳。
- 对 Fake-IP 域名，日志应出现 `[ICMP TRACE] ... (real target ...) using DIRECT`。
  工具最终仍可能显示其请求的 Fake-IP；中间跳应是实际路由器，真实终点 IP 可查日志。
  首次域名解析时间可能计入第一个探测的耗时。
- 同时运行多个 trace，核对序号、重复回包、超时、CPU 和内存。
- 分别在 Tailscale 开/关、Wi-Fi/有线切换、睡眠恢复后检查。
- 若出现 `[ICMP TRACE] setup failed` 或 `send failed`，保留错误日志；失败不应显示模拟成功。
- 本补丁解析 Fake-IP 时会访问真实目标的 DIRECT 路径，符合这里的本机网络诊断用途。

## 回退

关闭 `tun.icmp-trace` 即恢复该内核的原有 ICMP 路径；如需完全回退，停止相关进程后
换回备份的官方内核，并删除实验配置字段。不要把 `disable-icmp-forwarding: true`
当作绕过方法，它仍是上游的模拟回应模式。

## 源码与构建

- Mihomo 基线：`v1.19.31` / `ab405bad5beeeac8b003bb01f60f134f6df54471`
- sing-tun 基线：`v0.4.24` / `b50ae28a1409c7bce8e96e6c6966cf57d8ace754`
- 构建工具：Go 1.27.1；`CGO_ENABLED=0`，`GOOS=windows`，`GOARCH=amd64`，`with_gvisor`。
- 构建后 `work/mihomo/go.mod` 的本地 replace 指向相邻 `work/sing-tun` 目录。
- `scripts/build.sh` 下载固定提交的上游源码并应用本仓库补丁，然后构建 Windows x64 内核。
- 两个上游项目的许可证保存在仓库根目录，完整对应源码随测试版本一并提供。


## 从源码构建

安装 Go 1.27.1、Git、curl、tar 和 Bash，然后在本目录执行：

```bash
bash scripts/build.sh
```

Windows 可在 WSL 中构建，输出仍是 Windows x64 exe。源码包包含相邻的
`mihomo` 和 `sing-tun` 目录，可自行运行 Go 测试。

## GitHub 直接下载

- [下载 Windows x64 测试包](https://raw.githubusercontent.com/hbyq/mihomo-icmp-trace/main/downloads/mihomo-windows-amd64-icmp-trace-exp1.zip)
- [下载完整源码](https://raw.githubusercontent.com/hbyq/mihomo-icmp-trace/main/downloads/mihomo-icmp-trace-exp1-source.zip)
