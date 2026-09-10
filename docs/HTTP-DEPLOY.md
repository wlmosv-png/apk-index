# Streamable HTTP 部署与契约

这份文档只写**实测过**的行为。协议实现见 `src/apkindex/httpd.py`，
常量见 `src/apkindex/config.py`，工具清单以 `tools/list` 实际输出为准。

## 什么时候用 HTTP，什么时候用 stdio

| | stdio（`python -m apkindex.cli` / `apkindex.cli call`） | HTTP（`/mcp`） |
|---|---|---|
| 客户端能自己拉起进程 | 合适 | 不必要 |
| 客户端只能填一个 URL（手机 App 内的客户端） | 做不到 | **就用这个** |
| 索引缓存 | 共用同一份 `APK_INDEX_CACHE` | 同上 |

两者共用 `server.Server.handle()`，协议行为、工具集、返回信封**完全一致**。
差别只在传输层（帧、状态码、鉴权）。

## 启动

### 一次性拉起 / 重启（推荐，幂等）

```sh
# Android root shell 执行
sh tools/httpd-android.sh 8732
```

这个启动器做四件事，顺序固定：

1. `mount --bind` 三条路径进 chroot（**幂等**，已挂就跳过）：
   - `$APK_INDEX_HOME` → 容器内 `/apk`（代码 + 缓存）
   - `/data/local/tmp` → 同路径
   - `/storage/emulated/0` → 同路径
   目的是让客户端填的路径在容器内外指向同一个文件，不用猜容器内路径。
2. 按 cmdline 找出旧的 `apkindex import httpd` 进程并 kill（所以跑最新代码）。
3. `setsid chroot <Alpine rootfs> python3 -c "...httpd.serve(...)"` 起新进程。
4. `GET /mcp` 探活。

> **为什么从 Android 侧起、不在 Linux 工具环境里起**：工具环境跑完一条命令会按
> 进程组清理后台，服务跟着死。Android root + `setsid` 才活得久（实测跨多次调用存活）。

### 开机自启

```
<SERVICE.D>/apk_index_httpd.sh   # 等 boot_completed + rootfs 可用后调启动器
$LOG_DIR/service-boot.log    # 自启记录
$LOG_DIR/httpd-android.log   # 服务自己的访问日志（verbose）
```

依赖 宿主提供的 Alpine rootfs（在 App 私有目录下）。**卸载 宿主终端环境 或清它的数据，服务起不来**，
索引缓存也会跟着没 —— 但已索引的包本身不受影响，重装后 `loadApk` 重建即可。

## 路由与帧

| 请求 | 行为 |
|---|---|
| `POST /mcp` 单条请求 | `200` + JSON；客户端 Accept **只**接受 `text/event-stream` 时改发 SSE 单帧（内容一样） |
| `POST /mcp` 通知（无 id） | `202` 空 body |
| `POST /mcp` 批量数组 | `200` + JSON 数组 |
| `GET /mcp` | Accept 要 `text/event-stream` → 常驻 SSE 流（只发 `:` 注释帧保活，无 Content-Length）；否则 `200` 健康检查 |
| `DELETE /mcp` | `200`（回 501 会被很多客户端当成服务故障） |
| `OPTIONS` | `204` + CORS |
| 其他路径 | `404` |

健康检查长这样（**不要 token**，启动器靠它探活）：

```json
{"ok": true, "name": "apk-index", "version": "0.4.4", "transport": "streamable-http",
 "endpoint": "/mcp", "tools": 17, "maxRequestBytes": 4194304,
 "sessionMode": "stateless", "auth": "none"}
```

`sessionMode: stateless` 是明说的：`initialize` 会发 `Mcp-Session-Id` 头，
客户端带回来也接受，但**服务端不校验**。严格拒绝未知会话 id 会让实现松一点的
客户端直接卡死，而这里没有可泄漏的会话状态（真正的会话是 `sessionId` 参数，
那个是校验的）。

### 为什么默认回 JSON 而不是 SSE

规范允许两种。实测 ktor-client一进 `text/event-stream`
就切成"等流结束"的读法，白等一个 request_timeout。所以：**两边都接受 → JSON**，
只有明确只收 SSE 的客户端才给 SSE。

## 状态码映射

业务错误**不占用** HTTP 状态码：`tools/call` 的成功与失败都是 `200`，
成败看信封里的 `ok` 和 `code`。只有传输/协议层的错误才改状态码。

| 情况 | JSON-RPC code | HTTP |
|---|---|---|
| JSON 解析失败 | `-32700` | 400 |
| 非法请求 / 非 object / 路径不是 `/mcp` / body 超限 | `-32600` | 400 / **413** |
| 未知 JSON-RPC 方法（如把工具名当方法调） | `-32601` | **404** |
| 参数不合 schema | `-32602` | 400 |
| 内部异常 | `-32603` | 500 |
| 缺 token / token 不对 | `-32002` | **401** + `WWW-Authenticate: Bearer` |

两条实现取向：

- **413 前会把 body 读干净再回话**。直接回话就关连接，会把客户端写端打断，
  它只能看到 broken pipe 而不是 413。
- **意外异常必须回 500**。静默断连 + 空响应是最难查的故障形态。

## 大小与条数上限

| 常量 | 值 | 超了会怎样 |
|---|---|---|
| `APK_INDEX_MAX_BODY_BYTES` | 4 MiB | 413（不解析、不建索引） |
| `MAX_RESPONSE_BYTES` | 32 KiB | 只保留前 N 条，`truncated=true`，`hint` 里说明保了几条 |
| `MAX_ITEMS_BYTES` | 2 KiB | 该条被摘要化（**单条响应不套这个上限**，见下） |
| `DEFAULT_LIMIT` / `HARD_LIMIT` | 50 / 200 | 查询类工具的分页 |
| `MAX_DECOMPILE_LINES` | 400 | `decompile` 正文行数 |

单条响应为什么豁免：`decompile` 一次只返回一条，若按每条 2 KiB 摘要化，
被削掉的会是 `note`/`chain`/`engine` 这些**解释"这份代码从哪来"**的元数据，
正文反而留着 —— 方向刚好错。现在多条时先削正文、再考虑删别的。

## 鉴权

默认**只绑 127.0.0.1**：本机 App 能连，同网段连不上。

要加 token：

```sh
APK_INDEX_MCP_TOKEN='一串随机值' sh tools/httpd-android.sh 8732
```

（`APK_INDEX_TOKEN` 是等价的短别名。）生效后：

- 客户端带 `Authorization: Bearer <token>` **或** `X-Apk-Index-Token: <token>`；
- 缺或错 → `401` + JSON-RPC `-32002` + `WWW-Authenticate: Bearer realm="apk-index"`，
  **body 不解析**（不鉴权就先不读、不建索引）；
- 用 `hmac.compare_digest` 比，不走短路比较；
- `GET /mcp` 健康检查仍然免鉴权（启动器要靠它探活，且它不含任何包内容）。

用 401 不用 403：MCP 客户端一般把 401 读成"要凭据"，会提示去填 token。

**非回环地址 + 无 token = 拒绝启动**（`serve()` 直接返回 2 并打印原因）。
真要从局域网连，就自己 `--host 0.0.0.0` 并配好 token：索引是只读的，
但里面装的是别人 App 的代码结构。

还没做的：Unix socket + `SO_PEERCRED`（按对端 UID 放行）。比 token 硬，不用管凭据存放。

## decompile 的降级契约

`format` 取值：`auto`（默认）｜`java`｜`smali`｜`outline`。

`auto` 逐级试：jadx → baksmali → 索引重建视图，**一定带回正文**，并在
`items[0].chain` 里给出每一步的失败原因，例如：

```json
{"engine": "index-outline", "authoritative": false, "degraded": true,
 "chain": ["java:DECOMPILER_UNAVAILABLE 没找到 jadx：...",
           "smali:缺 baksmali/Java 环境"]}
```

只有 `engine=jadx`/`baksmali` 时 `authoritative=true`。
`index-outline` 是从 SQLite 索引重建的结构视图（签名 + 字符串/调用/字段引用清单），
**不是指令流**，别当反编译结果引用。

外部依赖：`JADX_HOME`（或 `APK_INDEX_JADX_HOME`）指 jadx；`BAKSMALI_JAR`（或
`APK_INDEX_BAKSMALI_JAR`）+ JDK 指 baksmali。都没有就只剩 `outline`，功能不断。

## 客户端配置例子

只能填 URL 的客户端：

```
http://127.0.0.1:8732/mcp
```

curl 全流程：

```sh
# 1) 握手（Mcp-Session-Id 在响应头里）
curl -si -X POST http://127.0.0.1:8732/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"curl","version":"1"},"capabilities":{}}}'

# 2) 工具清单
curl -s -X POST http://127.0.0.1:8732/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | head -c 600

# 3) 索引一个包再反编译（注意：JSON-RPC 的 method 恒为 tools/call，工具名在 params.name）
curl -s -X POST http://127.0.0.1:8732/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"loadApk","arguments":{"path":"/data/local/tmp/x.apk"}}}'
```

## 排障

| 现象 | 原因 / 怎么办 |
|---|---|
| 探活打印"起来了但探活失败" | `curl` 不在或首次加载慢。看 `GET /mcp` 手打一次；服务本身可能已经好了 |
| 启动器把自己的 shell 一起杀了 | 你的命令行里含 `apkindex import httpd` 字面量，被它的 kill 循环按 cmdline 匹配上。用 `apkindex[ ]import` 这类带通配/字符类的写法 |
| 客户端报路径不存在 | 容器内看不见宿主路径。确认三条 `mount --bind` 在：`grep ' apk$|/data/local/tmp' /proc/mounts` |
| 服务过一会儿没了 | 从 Linux 工具环境起的进程会被按进程组回收。改用 `tools/httpd-android.sh` |
| 端口 0 条监听 | `sh tools/httpd-android.sh 8732` 重启；日志 `$LOG_DIR/httpd-android.log` |
| 401 但确定设了 token | 环境变量要在**启动服务的那个 shell**里；自启脚本走 `<SERVICE.D>/`，改那里 |

## 已知缺口

- `loadPackage`（按包名直接索引 `/data/app` 里正在跑的 app）未实现：chroot 里读不到
  宿主 `/data/app`，得走"宿主 `pm path` → 拷到共享目录 → 容器内 `loadApk`"两段式。
- 无 UDS + `SO_PEERCRED`，本机其他 root 进程仍可用 token 连（token 明文放环境变量）。
- 加固包只能给加固特征 + 清单声明，拿不到真实类图（要脱壳或运行期 hook）。
