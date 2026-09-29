# honeypot-go

纯本地回环（loopback）运行的多协议蜜罐与交互诱捕服务。模拟常见服务入口，记录外来探测与攻击行为，
进行指纹识别、行为告警（带去重）与诱饵生命周期管理。所有网络交互只发生在 `127.0.0.1` / `::1`，
不连接、不依赖任何外部服务。

## 功能

- 多服务仿真并存：HTTP、SSH、FTP、通用 TCP，各自独立配置监听地址、横幅（banner）与响应行为，
  可独立启动 / 暂停 / 轮换 / 退役，互不影响。
- 会话级记录：每个入站连接生成独立会话，记录开始/结束时间、来源/本地地址、
  逐条入站载荷与出站响应（原始字节以 base64 持久化）、字节计数与结束原因。
- 指纹识别：依据握手特征与交互序列匹配已知扫描器/攻击工具（如 nmap、masscan、hydra、
  nikto、gobuster、curl 等），识别结果写入会话；无法识别时写入可区分标记 `unknown`。
- 诱饵生命周期：创建、暂停、轮换（新世代监听地址，旧连接不中断）、退役；
  退役后历史记录仍可查询。
- 告警去重：同一来源（归一化到 IP）在可配置窗口内的同类行为只产生一次告警；
  去重只抑制重复告警，绝不丢弃任何底层交互记录。
- 资源边界：并发连接数、单会话时长、单会话字节量、单会话事件数、持久化记录总量均有上限，
  超限行为确定且不会造成内存无界增长。
- 异常链路：慢速连接使用读/空闲 deadline 调度，不阻塞其他会话；连接中途断开时已捕获内容
  立即原子落盘；读写超时均有确定的 `close_reason` 语义。

## 目录结构

| 路径 | 职责 |
| --- | --- |
| `cmd/honeypot` | 命令行入口，加载配置并托管生命周期与优雅关停 |
| `internal/config` | 配置类型、默认值、JSON 加载与回环地址校验 |
| `internal/session` | 会话 / 事件 / 告警模型与文件持久化（原子写、FIFO 淘汰） |
| `internal/fingerprint` | 基于握手特征与交互序列的指纹匹配 |
| `internal/dedup` | 滑动窗口告警去重 |
| `internal/service` | HTTP/SSH/FTP/TCP 协议仿真、实例运行时与生命周期 Manager |
| `internal/honeypot` | 顶层装配与会话/告警查询 |

## 运行

零配置（内置一组回环演示端口）：

```sh
go run ./cmd/honeypot -data-dir ./honeypot-data
```

使用配置文件：

```sh
go run ./cmd/honeypot -config config.example.json
```

启动后可直接用本地工具验证：

```sh
curl http://127.0.0.1:8080/admin
printf 'SSH-2.0-Nmap_NES\n' | nc 127.0.0.1 2222
printf 'USER root\nPASS toor\nQUIT\n' | nc 127.0.0.1 2121
printf 'HELP\nQUIT\n' | nc 127.0.0.1 9000
```

## 持久化布局

所有记录位于 `DataDir`：

- `sessions/<id>.json`：每个会话一个文件，采用 `临时文件 + fsync + rename + fsync目录` 原子改写，
  进程崩溃或连接中断都不会产生半截/损坏文件。
- `alerts.jsonl`：每行一条告警（JSON），总量受 `MaxSessions` 约束，超出时丢弃最旧记录。

会话 ID 以纳秒时间戳为前缀，天然可按文件名排序。

## 配置项

根配置：

| 字段 | 说明 | 默认值 |
| --- | --- | --- |
| `DataDir` | 持久化目录 | `./honeypot-data` |
| `Limits` | 资源边界，见下表 | 见下 |
| `Dedup.Window` | 告警去重窗口 | `1m` |
| `Dedup.IncludeFingerprint` | 指纹是否参与去重键（true 时同行为不同工具分别告警） | `false` |
| `Fingerprints` | 自定义指纹规则；留空使用内置规则集 | 内置 |
| `Services[]` | 仿真服务列表，见下 | 无 |

`Limits`：

| 字段 | 说明 | 默认值 |
| --- | --- | --- |
| `MaxConcurrentConns` | 单个仿真实例最大并发连接，超出立即拒绝并记录 `concurrency_limit` | `64` |
| `SessionTimeout` | 单会话硬时长上限，到期强制关闭 | `5m` |
| `IdleTimeout` | 两次读到数据之间的最大空闲（慢速攻击据此终结） | `30s` |
| `MaxSessionBytes` | 单会话入站/出站累计字节上限，超出结束为 `byte_limit` | `1048576` |
| `MaxEventsPerSession` | 单会话事件条数上限，超出结束为 `event_limit` | `1024` |
| `MaxSessions` | 磁盘保留的会话（及告警）总量，FIFO 淘汰最旧记录 | `10000` |

`Services[]`：

| 字段 | 说明 |
| --- | --- |
| `Name` | 诱饵唯一名（生命周期操作以此引用） |
| `Protocol` | `http` / `ssh` / `ftp` / `tcp` |
| `Listen` | 必须是回环地址 `host:port`，端口 `0` 表示系统分配 |
| `Banner` | 横幅/服务标识：SSH 为版本串、FTP 为欢迎语、TCP 为连接问候、HTTP 为 `Server` 头 |
| `Enabled` | 启动时是否自动运行 |
| `Behavior.DefaultResponse` | 未命中定制规则时的默认响应 |
| `Behavior.Responses` | 按命令/路径前缀定制的响应表（键大小写不敏感） |
| `Behavior.ReadTimeout` / `WriteTimeout` / `IdleTimeout` | 协议级 I/O 超时，零值取全局默认 |

时间字段使用 Go duration 格式（如 `500ms`、`2m`）。

## 告警语义

- 告警由协议处理器在识别到特定行为时产生（去重在记录层完成）：
  - HTTP：`http_scanner_ua`（已知扫描器 UA）、`http_probe_path`（如 `/.env`、`/admin`、`/.git` 等）。
  - SSH：`ssh_probe`（完成 SSH 版本交换或继续发送握手字节）。
  - FTP：`ftp_login_attempt`（完整的 `USER` + `PASS` 登录尝试）。
  - 通用 TCP：按配置响应，不内置告警。
- 去重键默认为 `来源IP + 行为`；`IncludeFingerprint=true` 时追加指纹维度。
  因此「同一来源、同类行为、窗口内」只产生一条告警，窗口过后可再次产生。
- 每条告警记录包含时间、去重键、来源地址、服务名、行为、当时指纹与关联会话 ID。
- 去重不影响会话与事件：每次连接和每条载荷都独立完整落盘。

## 会话结束原因（`close_reason`）

| 值 | 语义 |
| --- | --- |
| `peer_closed` | 对端正常关闭连接 |
| `read_timeout` | 首个字节在读取超时内未到达 |
| `idle_timeout` | 已收到部分数据后空闲超时（慢速连接终结） |
| `write_timeout` | 写出响应超时 |
| `session_timeout` | 达到单会话硬时长上限 |
| `byte_limit` / `event_limit` | 达到单会话字节 / 事件上限 |
| `concurrency_limit` | 因并发连接上限被拒绝 |
| `shutdown` | 服务关停导致连接关闭 |
| `protocol_error` | 其他协议处理错误 |

## 测试

```sh
go test ./...
go test -race ./...
```

覆盖：多仿真并存、指纹匹配（ANY / 有序序列 / 协议隔离 / 未命中标记）、告警去重与不丢底层记录、
生命周期（暂停 / 轮换 / 退役与历史保留）、重启恢复、并发与单会话字节上限、总记录量 FIFO 淘汰、
慢速连接不阻塞与会话中途中断落盘。
