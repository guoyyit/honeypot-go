# honeypot-go

一套纯本地（仅监听回环地址）的多服务蜜罐与交互诱捕服务，用于模拟常见服务入口并捕获外来探测与攻击行为。所有仿真与探测交互均通过 `127.0.0.1` / `localhost` / `[::1]` 完成，不依赖任何外部服务或第三方数据库。

## 功能概览

- **四类服务仿真并存**：HTTP、SSH、FTP、通用 TCP。每个诱饵独立配置监听端口、横幅（banner）与响应行为，可独立启停，互不影响。
- **按会话组织的完整记录**：每个入站连接生成独立会话，记录开始/结束时间、来源地址、监听端点、服务世代、逐块载荷（Base64）、响应与系统事件。会话以 append-only JSONL 持久化，重启后回放恢复，不丢失、不损坏。
- **指纹识别**：根据握手特征与有序交互序列匹配已知扫描器/攻击工具；命中写入规则名，无法识别时写入可区分标记 `unknown:no-match`。
- **诱饵生命周期**：支持创建、暂停（pause）、恢复（resume）、轮换（rotate，世代 +1）与退役（retire）。生命周期变更只影响“是否接受新连接”，进行中的会话继续跑完；退役后历史记录仍可查询。
- **告警去重**：同一去重键在时间窗口内的同类行为只产生一次告警；窗口大小与参与匹配的字段（`source`/`signature`/`service`）均可配置。去重只影响是否再次告警，**不丢弃任何底层交互记录**。
- **资源边界**：并发连接数、单会话时长、单会话字节量、全局事件记录量都有硬上限，超限行为确定且不会导致内存无界增长。
- **异常链路**：每次读/写都带超时，慢速连接不会阻塞其它会话；连接中途断开时已捕获内容已逐块 `fsync` 落盘；读/写/会话超时都有固定的关闭原因。

## 目录结构

```
cmd/honeypot            命令行入口（加载配置、启动、信号优雅退出）
internal/config         配置类型、默认值、JSON 加载与校验（仅允许回环监听）
internal/session        会话模型、Recorder、append-only JSONL FileStore
internal/fingerprint    指纹规则、有序匹配器、未命中标记
internal/alert          告警模型、滑动窗口去重、JSONL 持久化
internal/service        ConnGate、确定性 I/O 封装与 HTTP/SSH/FTP/TCP 处理器
internal/honeypot       诱饵生命周期、装配、资源闸、会话/告警查询
examples/config.json    示例配置
```

## 快速开始

```bash
# 使用内置默认配置（回环端口 18080/10022/10021/19000）
go run ./cmd/honeypot

# 使用自定义配置与数据目录
go run ./cmd/honeypot -config examples/config.json -data ./data
```

向任意仿真端口发起连接即可产生会话。例如：

```bash
curl -s http://127.0.0.1:18080/
printf 'SSH-2.0-Nmap\r\n' | nc 127.0.0.1 10022
printf 'USER anonymous\r\nPASS a@b\r\nQUIT\r\n' | nc 127.0.0.1 10021
printf 'hello' | nc 127.0.0.1 19000
```

收到 `SIGINT`/`SIGTERM` 后停止接受新连接，等待在途会话结束（最多 10s）后退出。

## 配置项说明

时长字段支持 `"300ms"` / `"5s"` / `"2m"` 字符串，或纳秒整数。

| 字段 | 含义 |
| --- | --- |
| `data_dir` | 会话与告警持久化目录（`sessions/*.jsonl`、`alerts.jsonl`） |
| `limits.max_concurrent_conns` | 全局限发连接名额；超出立即拒绝并记录 `concurrency_limit` 会话 |
| `limits.session_timeout` | 单会话最长存活时间，到期关闭原因为 `session_timeout` |
| `limits.read_timeout` | 单次读等待上限，超时关闭原因为 `read_timeout` |
| `limits.write_timeout` | 单次写等待上限，超时关闭原因为 `write_timeout` |
| `limits.max_session_bytes` | 单会话载荷字节上限；超出后仅保留摘要 note，关闭原因为 `session_byte_limit` |
| `limits.max_records` | 全局持久化事件数上限；达到后新载荷不落盘并写入一条系统提示 |
| `dedup.window` | 告警去重滑动窗口（距上次活动时间） |
| `dedup.keys` | 参与去重键的字段，取值 `source` / `signature` / `service` |
| `services[].kind` | `http` / `ssh` / `ftp` / `tcp` |
| `services[].listen` | 监听地址，**必须显式写回环主机**，仅接受下表列出的合法写法 |
| `services[].banner` | 服务横幅；HTTP 中可覆盖响应体，SSH/FTP 为接入横幅，TCP 为接入即发 |
| `services[].enabled` | 是否随 `StartAll` 启动 |
| `services[].behavior.status` / `body` | HTTP 固定响应码与响应体 |
| `services[].behavior.response` | SSH/TCP 的固定响应；TCP 中填 `echo:` 表示原样回显 |

### 监听地址写法（强制回环）

监听地址在**配置加载阶段**与**运行期创建诱饵时**都会被校验（`config.ValidateListen`），任何非回环写法都会被明确拒绝；拒绝发生在打开监听套接字之前，因此服务启动后不存在任何绑定在非回环地址上的套接字。四类仿真（HTTP/SSH/FTP/TCP）规则相同，配置键与格式保持不变、无需迁移。

合法写法（主机部分必填，仅限回环）：

- `127.0.0.1:18099`
- `localhost:18099`
- `[::1]:18099`

被拒绝的写法及报错要点：

| 写法 | 拒绝原因 |
| --- | --- |
| `:18099` | 省略主机部分，会绑定到所有网卡；报错提示需显式加 `127.0.0.1`/`localhost`/`[::1]` 前缀 |
| `0.0.0.0:18099`、`192.168.x.x:18099`、其它具体网卡 IP | 非回环地址 |
| `[::]:18099` | IPv6 通配地址，等价于监听所有网卡 |
| `example.com:18099` | 主机名不是回环别名（仅 `localhost` 受支持） |
| `18099` | 不是 `host:port` 形式 |

## 会话记录格式

`data_dir/sessions/<session-id>.jsonl` 每行一条 JSON 记录，顺序为：

1. `meta`：会话元数据（ID、服务、类型、监听、来源、世代、开始时间）。
2. 若干 `event`：`seq` 单调递增，`dir` 为 `in`/`out`/`system`，载荷放 `data_b64`（Base64），截断/限流等写 `note`。
3. 可选 `fingerprint`：命中时为命中规则名；会话收尾时仍无任何命中则写未命中标记 `unknown:no-match`。
4. `end`：结束时间与确定的关闭原因。

每次追加写入都执行 `fsync`，因此即使进程被杀或客户端中途断开，已捕获内容也完整可读。`List` 只返回会话元数据（内存有界），需要载荷时按 ID 调用 `Get` 从磁盘读取。

### 指纹写入时机与告警的对应关系

- 处理器对**当前会话已捕获的全部入站内容**做指纹匹配；一旦命中，立即把命中规则名通过 `fingerprint` 记录追加到该会话文件，随后才依据命中结果归类并产生告警。
- 因此“指纹告警已触发”与“会话记录写入同一命中规则名”是同一次匹配的两个结果，二者可通过会话的 `source`（来源地址）与 `service`（诱饵名）相互核验，不会出现“告警已触发而记录仍是未命中”的不一致状态。
- 会话中任何时刻已捕获内容命中指纹，记录都会反映命中结果（指纹记录首次写入生效，取该会话最早命中的规则名）。
- 未命中任何规则的会话在收尾时统一写入可区分标记 `unknown:no-match`，且不会产生扫描器类告警（如 `http:scanner`）；普通行为告警（如 `http:request`）与指纹无关，照常产生。

### 关闭原因（确定语义）

| 原因 | 触发条件 |
| --- | --- |
| `client_closed` | 对端主动断开或非超时网络错误 |
| `session_timeout` | 达到 `session_timeout`（ctx 到期） |
| `read_timeout` | 单次读在 `read_timeout` 内无数据 |
| `write_timeout` | 单次写在 `write_timeout` 内未完成 |
| `session_byte_limit` | 会话双向载荷累计达到 `max_session_bytes` |
| `concurrency_limit` | 达到 `max_concurrent_conns`，连接被立即拒绝 |
| `protocol_done` | 协议正常结束（如 FTP `QUIT`） |
| `server_closed` | 服务端关闭（保留给显式关闭场景） |

## 告警语义

- 告警由协议处理器在关键行为处通过签名（signature）上报，去重键由配置的字段拼接后哈希得到。
- **窗口语义**：同一去重键距上一次活动的时间小于 `dedup.window` 时，只累加内存中的 `count` 与 `last_seen`，不再产出新告警；超过窗口再次出现则重新告警、计数重置。
- 仅“首次发出”的告警追加到 `data_dir/alerts.jsonl`（去重期的计数累加不重复写盘）。重启时回放该文件，历史告警仍可查询。
- 无论是否被去重，触发告警的原始交互都已作为会话 `event` 完整落盘。

主要签名（稳定字符串，便于在 `dedup.keys` / 外部分析中引用）：

- HTTP：`http:request`、`http:scanner`、`http:exploit`
- SSH：`ssh:connect`、`ssh:banner`、`ssh:scanner`
- FTP：`ftp:connect`、`ftp:login-attempt`、`ftp:anonymous`、`ftp:scanner`
- TCP：`tcp:connect`、`tcp:probe`

## 指纹规则

内置规则见 `internal/fingerprint`，按“全部模式在入站流中按顺序出现（大小写不敏感）”判定，且规则按服务类型隔离。例如：

- HTTP：`User-Agent: nmap`、`gobuster`、`nikto`、`sqlmap`、Shellshock `() { :; }`、`GET /admin`、`/.env`
- SSH：含 nmap/masscan 的 SSH 横幅、`SSH-1.0-libssh` 等
- FTP：`USER anonymous`、`USER ...` 后 `PASS ...`（暴破序列）、`HELP` 探测
- TCP：裸端口上的 `GET /`、TLS ClientHello（`0x16 0x03`）等

未命中时会话指纹字段统一为 `unknown:no-match`。

## 问题复现与验证命令

以下命令均可在本地直接复现，预期输出给出关键判定点。

### 指纹告警与会话记录一致性（nikto 场景）

```bash
# 启动服务（默认 HTTP 监听 127.0.0.1:18080）
go run ./cmd/honeypot -data /tmp/hp-data

# 另开终端，用带 nikto 特征的 UA 请求
curl -s -H 'User-Agent: Nikto/2.1.6' http://127.0.0.1:18080/

# 查看该会话记录（找到最新的 jsonl）
grep -h '"record":"fingerprint"' /tmp/hp-data/sessions/*.jsonl | tail -1
grep -h '"signature"' /tmp/hp-data/alerts.jsonl | tail -1
```

预期：

- 会话文件中指纹记录为 `{"record":"fingerprint","fingerprint":"nikto-scanner",...}`，而不是 `unknown:no-match`；
- `alerts.jsonl` 中存在一条 `"signature":"http:scanner"` 告警，且其 `source`/`service` 与该会话 meta 中的 `source`/`service` 完全一致；
- 对照：`curl -s -H 'User-Agent: my-client' http://127.0.0.1:18080/` 产生的会话指纹为 `unknown:no-match`，且只有 `http:request` 告警、没有 `http:scanner`。

### 缺省主机监听被拒绝

```bash
# 构造一份只写端口、省略主机的配置
cat >/tmp/bad.json <<'JSON'
{ "data_dir": "/tmp/hp-bad",
  "services": [ {"name":"wild","kind":"http","listen":":18099","enabled":true} ] }
JSON
go run ./cmd/honeypot -config /tmp/bad.json
```

预期：进程在配置加载阶段直接退出，错误信息类似
`load config: service "wild": listen ":18099" omits the host part and would bind all interfaces; prefix it with a loopback host such as 127.0.0.1, localhost or [::1]`；
此时尚未打开任何监听，`lsof -nP -iTCP:18099 -sTCP:LISTEN` 无输出。把 `listen` 改为 `127.0.0.1:18099`、`localhost:18099` 或 `[::1]:18099` 后即正常启动；启动后 `lsof` 只能看到回环地址上的监听套接字。

## 生命周期语义

- **Pause**：关闭监听，不再接受新连接；在途会话不受影响。
- **Resume**：在同一地址重新开始接单。
- **Rotate**：世代号加一，关闭旧监听并等待其 accept 循环退出，再在同一地址启动新监听；旧连接继续跑，新旧会话以 `generation` 区分。
- **Retire**：永久停止接单，世代不再变化；历史会话与告警永久保留、可查询；退役后不可 resume。

## 资源边界与并发模型

- 接收循环对每个连接使用非阻塞信号量 `ConnGate.TryAcquire`：拿不到名额立即关闭并记录拒绝会话，因此慢连接不会堆积或拖垮 accept。
- 每条连接独立 goroutine；所有 I/O 设置 deadline，ctx 约束单会话总时长。
- 内存中只保存会话元数据与有界计数，不缓存载荷；载荷实时落盘，从根上避免无界增长。
- 超字节/超记录后继续运行（只是不再保存多余载荷），行为可预测。

## 测试

```bash
go test ./... -race -count=1
```

覆盖场景：四类仿真并存、指纹命中/未命中/顺序匹配/类型隔离、指纹命中时告警规则名与会话记录一致（含 HTTP nikto 场景，不会“告警已触发而记录仍为未命中”）、多连接并发指纹识别不串线/不丢配（`-race`）、告警窗口去重与可配置键及重启恢复、暂停/恢复/轮换/退役、完整停止后以全新实例重启的多周期恢复（历史会话/载荷/指纹/告警完整、恢复后新写入可用）、并发上限/单会话字节上限/全局记录上限、慢速连接不阻塞他人、中途断开内容完整落盘、监听地址强制回环（缺省主机/非回环在配置加载与运行期创建时均被拒绝、监听套接字只绑定回环）。

## 安全说明

这是一个用于本地检测与研究的蜜罐：它只模拟协议表层交互，不提供真实文件系统/Shell/账号能力；默认且强制仅监听回环地址。请勿将其直接暴露到非受信网络。
