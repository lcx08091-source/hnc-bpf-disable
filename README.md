# HNC v4.0 — BPF Tether Offload Disabler

强制关闭 Android BPF tether offload，让 HNC v3.4.x 的 tc HTB 限速在
高通 SD8 Elite / 联发科旗舰等带 BPF 卸载的机型上真正生效。

## 原理

Android tethering 模块用 BPF 把数据包直接从上游接口（rmnet*）redirect
到下游接口（wlan2），完全绕过 Linux 网络栈。这导致 HNC 的 iptables
mark 和 tc qdisc 看不到这些包，限速失效。

但 AOSP 的 BPF 程序保留了一个 fallback 路径：

```c
if (stat_v->rxBytes + stat_v->txBytes + L3_bytes > *limit_v)
    TC_PUNT(LIMIT_REACHED);  // 把包还给 Linux 网络栈
```

`tether_limit_map` 是一个 `HASH<uint32_t iif, uint64_t limit>` map。
默认 limit = `UINT64_MAX`（永不超限）。我们写 `limit = 0` →
所有包永远超限 → 全部 TC_PUNT → Linux 网络栈接管 → tc 限速生效。

这是 Google 自己设计的合法兜底路径，**不是 hack**。

## 怎么编译

### 方法 A：GitHub Actions（推荐，零本地依赖）

1. **fork 这个 repo 到你自己的 GitHub 账号**
2. 进入你 fork 的 repo → Actions 选项卡 → 同意启用 workflows
3. 第一次手动触发：Actions → "Build BPF Offload Disable" → "Run workflow"
4. 等 1-2 分钟编译完成
5. 进入 workflow run → 滚到底部 "Artifacts" → 下载 `bpf_offload_disable-aarch64.zip`
6. 解压得到 `bpf_offload_disable` 二进制（约 700 KB，static 链接 musl/bionic libc）

### 方法 B：本地 NDK

```bash
# 装 Android NDK r26d 之后：
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang \
    -static -O2 -Wall -o bpf_offload_disable src/bpf_offload_disable.c
```

## 怎么用

```bash
# 1. 推到手机
adb push bpf_offload_disable /data/local/tmp/
adb shell su -c "chmod 755 /data/local/tmp/bpf_offload_disable"

# 2. 看当前 BPF limit_map 状态
adb shell su -c "/data/local/tmp/bpf_offload_disable status"

# 3. 自动检测默认上游路由并禁用卸载
adb shell su -c "/data/local/tmp/bpf_offload_disable auto"

# 4. 或者手动指定接口
adb shell su -c "/data/local/tmp/bpf_offload_disable disable rmnet_data2"

# 5. 恢复（重新启用卸载）
adb shell su -c "/data/local/tmp/bpf_offload_disable enable rmnet_data2"
```

## SELinux 注意

`tether_limit_map` 的 owner 是 `AID_NETWORK_STACK`。即使是 root，
SELinux enforcing 模式下默认可能拒绝写。

如果 disable 命令报 `EPERM (Operation not permitted)`：

- **KernelSU**: 需要给 `su` context 加 BPF map 写权限
- 临时验证：`setenforce 0` 然后再跑 disable，看是否成功（验证用，
  不要常态使用）

如果 `cat /sys/fs/bpf/tethering/map_offload_tether_limit_map` 能正常输出，
说明 SELinux 至少允许 read，那 write 大概率也允许。

## 已验证的环境

- Android 16, kernel 6.6.102, KernelSU/SukiSU
- realme RMX5010 (SD8 Elite), ColorOS, rmnet_data2 ifindex=20
