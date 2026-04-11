/*
 * bpf_offload_disable.c — HNC v4.0
 *
 * 用 bpf() syscall 直接操作 Android tethering BPF tether_limit_map，
 * 强制让 BPF tether offload 把所有数据包 punt 回 Linux 网络栈，
 * 从而让 HNC 的 tc HTB 限速重新生效。
 *
 * AOSP 源码（packages/modules/Connectivity/bpf_progs/offload.c）：
 *
 *   DEFINE_BPF_MAP_GRW(tether_limit_map, HASH, TetherLimitKey, TetherLimitValue, 16, TETHERING_GID)
 *
 *   if (stat_v->rxBytes + stat_v->txBytes + L3_bytes > *limit_v) TC_PUNT(LIMIT_REACHED);
 *
 * key   = uint32_t  iif (上游接口 ifindex)
 * value = uint64_t  limit (剩余字节配额)
 *
 * 把 limit 设成 0 → 永远超限 → 永远 TC_PUNT → 包回到 Linux 网络栈
 *
 * 用法：
 *   bpf_offload_disable disable [iif]   设 limit=0，禁用卸载（默认所有 entry）
 *   bpf_offload_disable enable  [iif]   设 limit=UINT64_MAX，恢复卸载
 *   bpf_offload_disable status          显示当前 limit_map 内容
 *   bpf_offload_disable auto            自动检测当前默认路由的 upstream，禁用之
 *
 * 编译（NDK aarch64）：
 *   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang \
 *       -static -O2 -Wall -o bpf_offload_disable bpf_offload_disable.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

#define LIMIT_MAP_PIN "/sys/fs/bpf/tethering/map_offload_tether_limit_map"
#define UINT64_MAX_VAL ((uint64_t)0xFFFFFFFFFFFFFFFFULL)

/* ────────── bpf() syscall 包装 ────────── */

static int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

/* 从 pin path 取得 map fd */
static int bpf_obj_get(const char *pathname) {
    union bpf_attr attr = {0};
    attr.pathname = (uint64_t)(unsigned long)pathname;
    return bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

/* 写 map element */
static int bpf_map_update(int map_fd, const void *key, const void *value, uint64_t flags) {
    union bpf_attr attr = {0};
    attr.map_fd = map_fd;
    attr.key    = (uint64_t)(unsigned long)key;
    attr.value  = (uint64_t)(unsigned long)value;
    attr.flags  = flags;
    return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

/* 读 map element */
static int bpf_map_lookup(int map_fd, const void *key, void *value) {
    union bpf_attr attr = {0};
    attr.map_fd = map_fd;
    attr.key    = (uint64_t)(unsigned long)key;
    attr.value  = (uint64_t)(unsigned long)value;
    return bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

/* 遍历 map keys */
static int bpf_map_get_next_key(int map_fd, const void *key, void *next_key) {
    union bpf_attr attr = {0};
    attr.map_fd   = map_fd;
    attr.key      = (uint64_t)(unsigned long)key;
    attr.next_key = (uint64_t)(unsigned long)next_key;
    return bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

/* ────────── 辅助：根据接口名取 ifindex ────────── */

static uint32_t iface_to_ifindex(const char *iface) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/ifindex", iface);
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    uint32_t idx = 0;
    if (fscanf(fp, "%u", &idx) != 1) idx = 0;
    fclose(fp);
    return idx;
}

/* 从 /proc/net/route 读默认路由的出口接口名 */
static int get_default_upstream(char *out, size_t outlen) {
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp) return -1;
    char line[512];
    /* 跳过表头 */
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return -1; }

    while (fgets(line, sizeof(line), fp)) {
        char iface[64];
        unsigned long dest, mask;
        if (sscanf(line, "%63s %lx %*s %*s %*s %*s %*s %lx", iface, &dest, &mask) >= 2) {
            if (dest == 0) {  /* 默认路由 */
                size_t n = strlen(iface);
                if (n >= outlen) n = outlen - 1;
                memcpy(out, iface, n);
                out[n] = '\0';
                fclose(fp);
                return 0;
            }
        }
    }
    fclose(fp);
    return -1;
}

/* ────────── 命令实现 ────────── */

static int do_status(void) {
    int fd = bpf_obj_get(LIMIT_MAP_PIN);
    if (fd < 0) {
        fprintf(stderr, "ERROR: bpf_obj_get(%s): %s\n", LIMIT_MAP_PIN, strerror(errno));
        fprintf(stderr, "       (检查 BPF tether offload 是否激活，以及当前 SELinux context)\n");
        return 1;
    }

    printf("BPF tether_limit_map (path=%s):\n", LIMIT_MAP_PIN);

    uint32_t key = 0, next_key;
    int found = 0;

    /* 第一次调用传 NULL 拿第一个 key */
    if (bpf_map_get_next_key(fd, NULL, &next_key) == 0) {
        do {
            uint64_t value = 0;
            if (bpf_map_lookup(fd, &next_key, &value) == 0) {
                /* 反查 ifindex 对应的接口名 */
                char iface_name[64] = "?";
                DIR *d = opendir("/sys/class/net");
                if (d) {
                    struct dirent *e;
                    while ((e = readdir(d))) {
                        if (e->d_name[0] == '.') continue;
                        if (iface_to_ifindex(e->d_name) == next_key) {
                            strncpy(iface_name, e->d_name, sizeof(iface_name) - 1);
                            iface_name[sizeof(iface_name) - 1] = '\0';
                            break;
                        }
                    }
                    closedir(d);
                }

                if (value == UINT64_MAX_VAL) {
                    printf("  iif=%-3u (%s)  limit=UINT64_MAX (卸载激活，未限制)\n",
                           next_key, iface_name);
                } else if (value == 0) {
                    printf("  iif=%-3u (%s)  limit=0 (卸载已禁用)\n",
                           next_key, iface_name);
                } else {
                    printf("  iif=%-3u (%s)  limit=%llu bytes\n",
                           next_key, iface_name, (unsigned long long)value);
                }
                found++;
            }
            key = next_key;
        } while (bpf_map_get_next_key(fd, &key, &next_key) == 0);
    }

    if (!found) printf("  (空)\n");
    close(fd);
    return 0;
}

static int set_limit_for_ifindex(uint32_t ifindex, uint64_t limit, const char *desc) {
    int fd = bpf_obj_get(LIMIT_MAP_PIN);
    if (fd < 0) {
        fprintf(stderr, "ERROR: bpf_obj_get: %s\n", strerror(errno));
        return 1;
    }

    int rc = bpf_map_update(fd, &ifindex, &limit, BPF_ANY);
    close(fd);

    if (rc < 0) {
        fprintf(stderr, "ERROR: bpf_map_update_elem(iif=%u, limit=%llu): %s\n",
                ifindex, (unsigned long long)limit, strerror(errno));
        if (errno == EPERM) {
            fprintf(stderr, "       (SELinux 拒绝写 BPF map。需要给 su context\n");
            fprintf(stderr, "        添加 'allow su * bpf {map_create map_read map_write}' 规则。\n");
            fprintf(stderr, "        KernelSU: 在 /data/adb/ksu/ 加 SELinux policy patch)\n");
        }
        return 1;
    }
    printf("OK: iif=%u %s (limit=%llu)\n",
           ifindex, desc, (unsigned long long)limit);
    return 0;
}

static int do_disable(uint32_t ifindex) {
    return set_limit_for_ifindex(ifindex, 0, "卸载已禁用");
}

static int do_enable(uint32_t ifindex) {
    return set_limit_for_ifindex(ifindex, UINT64_MAX_VAL, "卸载已恢复");
}

/* 自动检测当前默认路由的 upstream 接口并禁用卸载 */
static int do_auto(void) {
    char iface[64];
    if (get_default_upstream(iface, sizeof(iface)) != 0) {
        fprintf(stderr, "ERROR: 找不到默认路由接口（无网络？）\n");
        return 1;
    }
    uint32_t ifindex = iface_to_ifindex(iface);
    if (ifindex == 0) {
        fprintf(stderr, "ERROR: 接口 '%s' 没有 ifindex\n", iface);
        return 1;
    }
    printf("自动检测到默认上游: %s (ifindex=%u)\n", iface, ifindex);

    /* 先看 limit_map 里有没有这个 entry。如果没有，BPF 程序遇到 NULL limit_v 会
     * 走 TC_PUNT(NO_LIMIT_ENTRY) 分支，效果一样（卸载失效），无需写 map */
    int fd = bpf_obj_get(LIMIT_MAP_PIN);
    if (fd >= 0) {
        uint64_t v;
        if (bpf_map_lookup(fd, &ifindex, &v) != 0) {
            printf("注意: limit_map 里没有 iif=%u 的 entry，BPF 程序会自动 punt 这条接口的所有包。\n", ifindex);
            close(fd);
            return 0;
        }
        close(fd);
    }

    return do_disable(ifindex);
}

/* ────────── main ────────── */

static void usage(const char *prog) {
    fprintf(stderr,
        "HNC v4.0 BPF Offload Control\n\n"
        "用法:\n"
        "  %s status                     显示当前 limit_map 状态\n"
        "  %s disable <iface|ifindex>    禁用某接口的 BPF 卸载\n"
        "  %s enable  <iface|ifindex>    恢复某接口的 BPF 卸载\n"
        "  %s auto                       自动检测默认路由 upstream 并禁用\n\n"
        "示例:\n"
        "  %s status\n"
        "  %s disable rmnet_data2\n"
        "  %s disable 20\n"
        "  %s auto\n",
        prog, prog, prog, prog, prog, prog, prog, prog);
}

/* 解析 iface 参数：可以是接口名或 ifindex 数字 */
static uint32_t parse_iface_arg(const char *arg) {
    if (!arg) return 0;
    /* 如果全是数字，当 ifindex */
    int all_digit = 1;
    for (const char *p = arg; *p; p++) {
        if (*p < '0' || *p > '9') { all_digit = 0; break; }
    }
    if (all_digit) {
        return (uint32_t)atoi(arg);
    }
    return iface_to_ifindex(arg);
}

int main(int argc, char *argv[]) {
    if (argc < 2) { usage(argv[0]); return 1; }

    if (strcmp(argv[1], "status") == 0) {
        return do_status();
    }
    else if (strcmp(argv[1], "disable") == 0) {
        if (argc < 3) { usage(argv[0]); return 1; }
        uint32_t ifindex = parse_iface_arg(argv[2]);
        if (ifindex == 0) {
            fprintf(stderr, "ERROR: 无法解析接口 '%s'\n", argv[2]);
            return 1;
        }
        return do_disable(ifindex);
    }
    else if (strcmp(argv[1], "enable") == 0) {
        if (argc < 3) { usage(argv[0]); return 1; }
        uint32_t ifindex = parse_iface_arg(argv[2]);
        if (ifindex == 0) {
            fprintf(stderr, "ERROR: 无法解析接口 '%s'\n", argv[2]);
            return 1;
        }
        return do_enable(ifindex);
    }
    else if (strcmp(argv[1], "auto") == 0) {
        return do_auto();
    }
    else {
        usage(argv[0]);
        return 1;
    }
}
