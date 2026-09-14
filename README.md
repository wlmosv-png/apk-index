# apk-index —— Android 逆向 / Xposed 模块开发用的 APK 索引 MCP Server

[![M8ven Score](https://m8ven.ai/badge/mcp/wlmosv-png/apk-index)](https://m8ven.ai/mcp/wlmosv-png/apk-index)
静态索引 APK / split APK / AAR / 裸 dex / vdex / compact-dex，给 Agent 提供
「查类、查成员、查签名、查字符串、查交叉引用、生成 hook 起手块」的只读能力。
纯 Python 3 标准库（zipfile / sqlite3 / struct / json / hashlib），stdio 上说 MCP JSON-RPC 2.0。

## 运行要求
- Python >= 3.10，无第三方依赖
- 可选：JDK 的 `javac`（AAR fixture）与 `javap`（.class 交叉校验）；缺省时用内置 `tools/classwrite.py` 兜底
- 只读挂载：索引写 `APK_INDEX_CACHE`（默认 `~/.cache/apk-index`），永不写源文件

## 多客户端隔离（0.5.1+）

同时开两个对话 / 两个工作连同一个实例时，会话按 **owner（租户）** 隔离：

- HTTP：客户端 `initialize` 后回传 `MCP-Session-Id` 请求头 → 每个客户端一个
  owner；不带头的老客户端归 `default`（兼容）。
- stdio：每个进程随机 owner（可用环境变量 `APK_INDEX_OWNER` 固定）。
- CLI：`APK_INDEX_OWNER` 或 `cli`。

隔离语义：`sessionList` 只显示本客户端的会话；`unload` 只解除自己的引用，
**索引文件全局共享**（同一包只建一次索引，多客户端 load 命中缓存），
最后一个引用者释放时才删文件。跨进程写索引有文件锁（`<db>.lock`），
两个客户端同时索引同一新包不会互相踩。

## 注册到 MCP 客户端
```json
{
  "mcpServers": {
    "apk-index": {
      "command": "python3",
      "args": ["-m", "apkindex.mcp", "--stdio"],
      "env": {
        "PYTHONPATH": "/data/local/tmp/apk-index/src",
        "APK_INDEX_CACHE": "~/.cache/apk-index",
        "APK_INDEX_ALLOWED_ROOTS": "/sdcard:/data/local/tmp"
      }
    }
  }
}
```
`APK_INDEX_ALLOWED_ROOTS`（冒号分隔）是路径白名单，越界一律 `INVALID_PATH` —— 防止越权读宿主隐私文件。

## 23 个工具
| 分类 | 工具 | 一句话 |
|---|---|---|
| 装载 | `loadApk` | APK(+split 目录) → 会话；返回指纹 / manifest 摘要 / 组件 / 加固探测 |
| 装载 | `loadAar` | classes.jar + R.txt + consumer-rules.pro + jni/\<abi\>/*.so，可 `mergeInto` 并进 App 会话 |
| 装载 | `loadDex` | 裸 classes.dex / vdex / compact-dex，可追加进已有会话 |
| 会话 | `sessionList` / `stats` / `unload` | 忘了 sessionId 先 list；stats 看体量；unload 删登记（`keepFiles` 可选） |
| 查询 | `searchClasses` | exact / prefix / regex，`scope=app|lib|all`，`packageFilter` |
| 查询 | `listMembers` | 类内方法与字段，`include` 走 namePattern |
| 查询 | `getSignature` | 一个类或成员 → smali / reflector / java / helper-ktx 四形态 + hook 起手块 + 注解（含 visibility） |
| 查询 | `searchByString` | 常量字符串反查方法（contains/exact/regex，按命中数聚合排序） |
| 查询 | `findImplementations` | 接口实现 / 父类子类，含传递继承链 |
| 查询 | `xref` | callers / callees，`depth` 控制跳数 |
| 代码 | `decompile` | `outline`（骨架）/ `smali` / `java`，`maxLines` 截断 |
| 生成 | `matchSignature` | 只给结构条件（参数个数/类型/返回值/引用字符串）→ 候选成员 + 可粘 DSL |
| 生成 | `diffSessions` | 两版本差分：exact-structure / structural-similarity / added / removed（入参 `sessionA`/`sessionB`） |
| 综合 | `probe` | 一句人话问题 → 抽字面量/类名/关键词，串起 checkPacker+stats+各查询的证据包 |
| 探测 | `checkPacker` | 识别加固与 dex 加壳证据，只识别不静默脱壳 |
| 清单 | `listManifest` | 会话里的完整 manifest 摘要：包/版本/SDK/权限/四大组件/native 库，可按组件类型与 exported 过滤 |
| 清单 | `findComponent` | 按名字/类型/exported 精确定位一个组件（比 listManifest 窄） |
| 资源 | `searchResources` | resources.arsc 条目枚举（type/name/typeId）；解析失败报 NOT_FOUND 不装可用 |
| 资源 | `resourceRefs` | 找代码里引用某资源的方法：字符串常量 + const-class 真实 xref |
| 安全 | `resourceSecurity` | 一页安全面：exported 组件、危险权限、native 库、资源表可用性 |
| 运维 | `doctor` | 只读缓存体检：逐会话 quick_check / schemaVersion / 体积 / 未登记 db 文件 |

## 返回契约（每个工具都保证）
- 成功：`{ok:true, sessionId, total, items[], truncated, hint, tool, elapsedMs, ...专有字段}`
- 失败：`{ok:false, code, message, suggestion, hint}`
- `items` 上限 100 条、单 item ≤ 32KB；超出置 `truncated:true`，`hint` 说明怎么收窄
- `hint` 在成功与失败两种 envelope 里都恒存在，客户端只看一个字段就能决定下一步
- 错误码：`INVALID_PATH` `NOT_FOUND` `CLASS_NOT_FOUND` `INVALID_REFERENCE` `SESSION_NOT_FOUND`
  `APK_TOO_LARGE` `PACKED_DEX` `ENCRYPTED` `BACKEND_MISSING` `INTERNAL`

## 自测
```bash
bash build.sh                              # 打 tar 分发包
python3 tools/make_fixture.py --out fixtures
APK_INDEX_CACHE=$PWD/.cache python3 tests/test_tools.py
# 真机样本（混淆目标 + 跨版本差分）：
APK_INDEX_TEST_REAL_APK=/sdcard/Download/a.apk,/sdcard/Download/b.apk python3 tests/test_tools.py
```

## 已知边界
- 只读静态索引，不脱壳、不改二进制；加壳 APK 只报证据与 `PACKED_DEX`
- 无 JDK 时 `decompile(java)` 是内置可读伪 java（保留控制流与常量，不做数据流还原）
- dex 解码是 mterp 子集，遇到未覆盖 opcode 标 `partial:true` 而不是猜
- 未修问题清单见 `TESTPLAN.md`（真机 dex 的 mUTF-8 lone surrogate 已修，剩余为错误码与差分阈值）


## 参数与行为速查（对齐 tools/list 实测输出）

23 个工具：`loadApk` `loadAar` `loadDex` `sessionList` `unload` `stats` `checkPacker`
`searchClasses` `listMembers` `getSignature` `searchByString` `findImplementations`
`xref` `decompile` `matchSignature` `diffSessions` `probe`
`listManifest` `findComponent` `searchResources` `resourceRefs` `resourceSecurity` `doctor`。

### 会话与索引

- `loadApk(path, splits?, fromDevice?, packageName?, backend?)`：**按 dex 内容去重**。
  同一个 APK 无论重命名还是重打包，只要 dex 字节集合不变，拿回的是**同一个 `sessionId`**
  和同一份索引。想强制重来用 `unload(keepFiles=false)` 再 load。
- **参数名写错会直接拒收**（`BAD_ARGUMENT` + 有效参数列表），不再静默丢弃。以前把
  `searchClasses` 的 `kind` 写成 `match`，regex 不生效、返回 `total=0`，看着就像
  "这个包里根本没有"——假的空结果比崩溃更害人。注意两个搜索工具的参数名不同：
  `searchClasses(query, kind=exact|prefix|regex)`，`searchByString(text, match=contains|exact|regex)`。
- `loadAar(path, mergeInto?)`：读 `classes.jar` / `R.txt` / `consumer-rules.pro` /
  `jni/**/*.so`。**`mergeInto` 是"并进宿主会话"**，宿主的 `stats` 会多出 library 类；
  需要干净的对照会话时别用 `mergeInto`。
- `unload(sessionId, keepFiles?)` / `sessionList()` / `stats(sessionId)` /
  `checkPacker(sessionId)`：加固包在 `checkPacker` 里给壳特征与真实 dex 位置；
  静态可索引类数为 0 时会明确写"索引不到不等于没有"。

### 查询

- `searchClasses(sessionId, query, kind=exact|prefix|regex, scope=app|library|all, packageFilter, annotatedWith, limit)`
  —— `annotatedWith` 只回类上带该注解的（`@Keep`、`dalvik.annotation.Keep`、`Lkotlin/Metadata;` 三种写法都认），混淆包里挑名字稳定的锚点就用它。
- `listMembers(sessionId, class, include, namePattern, scope, withStrings, limit)`
- `getSignature(sessionId, class, member, scope)`：一个类（或一个成员）的完整外形。注解走 `annotations`：`descriptor / javaName / visibility(build|runtime|system) / values`。
- `searchByString(sessionId, text, match=contains|exact|regex, minLen, scope, methodLimit, limit)`
- `findImplementations(sessionId, interface|superClass, method, transitive, includeAbstract, scope, limit)`
  —— 裸类名可用（等于该类的实现/继承查找）。
- `xref(sessionId, method, direction=callers|callees|both, depth, scope, limit)`
  —— `method` 支持三种写法：`com.a.b.C`（整类全部成员的引用）、`com.a.b.C->m(sig)`、
  `com.a.b.C#m(sig)`；认不出来时报 `NOT_FOUND` 并把**原样入参**带回来，不静默返回空。
- `matchSignature(sessionId, params, returnType, namePattern, packagePrefix, modifiers,
  requireConstructor, invokedMethods, accessedFields, referredStrings, scope, limit)`
  —— `params` 支持 `any` 与具体类型混写；参数个数上限 8（不是 3）；
  `packagePrefix` 同时匹配 `com/example/demo` 与 `com.example.demo` 两种存法。
- `decompile(sessionId, target, format=java|smali, maxLines)`：三档兜底
  SMALI → JAVA+SMALI → SMALI，结果里标 `backend`/`format`/`truncated`；
  JADX 不存在、崩了或导不出源码时**不会**装作成功。

### 差分与聚合

- `diffSessions(sessionA, sessionB, scope, minScore, limit)`：条目按 `kind` 分三种，
  **键不一样** —— `renamed` 有 `from`/`to`/`score`/`how`/`fromDescriptor`/`toDescriptor`/
  `packageFrom`/`packageTo`/`methodsOnlyInA`/`methodsOnlyInB`；`added`/`removed` 只有
  `class`/`descriptor`/`superClass`/`source`/`methodCount`/`sampleMethods`。
  同一个会话自己比是合法的，结果为空差分。
  改名配对是启发式（同外形 + 同常量），`how` 说明依据；库类混进旧会话会搅动候选集，
  所以对照实验要在没被 `mergeInto` 污染过的会话上做。
- `probe(sessionId, question, target?, maxDepth?, limit)`：一句问题跑完整套侦察
  （引号字面量→字符串检索、点号/驼峰→类检索、中文串→UI 文案检索、加固→提示脱壳）。
  **给了 `target` 就连带 `xref` + `getSignature` + `decompile` 深挖**；问"有哪些实现类/
  子类"时给 `implementations` 分节。深挖失败另放 `xrefErrors`，不会把整次 probe 打死。

### 清单、资源与安全面（0.5.0 新增）

- `listManifest(sessionId, componentType?, query?, exported?, limit)` —— 数据在 `loadApk`
  时已写入会话 summary，查询不重新解包。`componentType=component` 看全部四类；
  `exported=true` 只匹配清单里**显式** true 的组件，未声明（None）不算——Android 默认规则
  和显式 false 不是一回事，安全审计上混淆这两者会给出假的干净列表。
- `findComponent(sessionId, name?, componentType?, exported?, limit)` —— `name` 支持短名
  后缀匹配（`.MainActivity` 和 `MainActivity` 都能命中）。
- `searchResources(sessionId, query?, match, resourceType?, limit)` —— best-effort 解析
  resources.arsc（纯 stdlib，条目样本上限 512）。解析不了时**报 `NOT_FOUND` + notes**，
  不返回 ok+空列表冒充"这个包没有资源"。
- `resourceRefs(sessionId, resource?, resourceType?, limit)` —— 两种证据：DEX 字符串常量
  （`app_name` / `R.string.app_name`）与 const-class（`R$string` / `BuildConfig`）。
  0 命中不等于没用到：`getIdentifier`、XML 直接引用、插件化加载都不留这两种痕迹，
  hint 里会说明。
- `resourceSecurity(sessionId)` —— 单条目聚合，适合跨版本 diff：包/SDK/权限/危险权限/
  exported 组件/native 库/资源类型。
- `doctor()` —— 只读：catalog 里每个会话的 db 存在性、`PRAGMA quick_check`、schemaVersion、
  缓存总大小、未登记的 `.db` 文件。它**不修**任何东西；处置是 `unload` + `loadApk` 重建。

注意：`loadAar(mergeInto=...)` 在 0.5.0 前会把库自己的 manifest 顶掉宿主清单；已修，
但**旧的混合会话要 `force=true` 重建**才能拿回正确的组件与安全面。

### 命令行

```bash
PYTHONPATH=src python3 -m apkindex.cli doctor fixtures/demo-v1.apk
PYTHONPATH=src python3 -m apkindex.cli sessions
PYTHONPATH=src python3 -m apkindex.cli tools
PYTHONPATH=src python3 -m apkindex.cli call loadApk '{"path":"fixtures/demo-v1.apk"}'
PYTHONPATH=src python3 -m apkindex.cli call xref '{"sessionId":"ses_xxx","method":"com.example.demo.User","direction":"callers"}'
PYTHONPATH=src python3 -m apkindex.cli pull com.tencent.mm   # adb 在连时才可用
# 子命令只有 tools/call/pull/doctor/sessions；具体查询一律走 call <tool> '<json>'
```

### 从设备取包（adb）

没有独立脚本，走 `loadApk` 的入参：

```jsonc
{ "name": "loadApk",
  "arguments": { "fromDevice": true, "packageName": "com.example.app",
                 "path": "" } }
```

`fromDevice=true` 时依次 `adb shell pm path <pkg>`（拿 base.apk 与 split APK 全部路径）
→ `adb shell dumpsys package <pkg>`（取 versionName/versionCode/minSdk/targetSdk，
和清单里的值互相校正）→ `adb pull` 到缓存目录再索引。`ADB` 环境变量指定 adb 路径
（默认 `adb_bin()` 的探测结果）。找不到 adb、设备没授权或超时都报 `ADB_UNAVAILABLE`
并给出下一步；**不假装能拉到自己拉不动的东西** —— 系统分区或受保护路径请在已 root
的机器上直接把 `/data/app/~~xxxx/.../base.apk` 当 `path` 传进来。

### 自测

```bash
python3 tests/test_tools.py                    # 38 组
APK_INDEX_TEST_REAL_APK=/path/a.apk,/path/b1.apk,/path/b2.apk python3 tests/test_tools.py
```

真机校准样本：TGAutoSign 1.2.1（1131 类，索引 ~1.6 s）、LocusMimic 2.0.0 ↔ 2.0.2
（差分识别 12 组改名候选）。只读校验用 `APK_INDEX_CACHE` + `APK_INDEX_ALLOWED_ROOTS`
把索引和读取范围钉在临时目录里。

`apkindex.cli doctor` 的 `ok:false` 只代表依赖不齐：缺 `aapt2` / `tools/dexlib.jar` / `tools/baksmali.jar` / `tools/apktool.jar` / `jadx/bin/jadx` 时资源与反编译走降级路径，索引与结构化查询不受影响（缺什么会逐项列名，不猜）。

## Streamable HTTP 传输（给只能填 URL 的客户端）

```bash
python3 -m apkindex.cli serve-http --host 127.0.0.1 --port 8732
# 手机上更靠谱的是这个（Android root，服务不会跟着工具环境一起被回收）：
sh tools/httpd-android.sh 8732
```

端点 `http://127.0.0.1:8732/mcp`：POST 一条 JSON-RPC → 200；客户端 `Accept` 里写了
`text/event-stream` 就回 SSE 单帧（`event: message` + `data: <同一份 JSON>`），
只要 `application/json` 就回裸 JSON —— Kotlin/Java 系的 MCP SDK 常常只认 SSE。
通知（无 id）→ 202 空 body；批量 → 200 + 数组；`GET` → 健康检查（`Accept` 要 event-stream
则开常驻流，只发注释帧保活）；`DELETE` → 200（回 501 会被客户端判成服务挂了）。
`initialize` 的应答带 `Mcp-Session-Id` 与 `MCP-Protocol-Version` 头（只发不校验：
拒绝未知会话 id 会让实现松一点的客户端直接卡死，本服务无状态可泄漏）。
与 stdio 版共用同一个 `Server.handle()`，23 个工具、参数校验、响应体积预算完全一致。
默认只绑回环；本机 loopback 与宿主 Android 是同一个 network namespace，
所以手机上的 App（例：LSPilot 的 MCP 拓展 → 本地 → 新建 → Streamable HTTP）
直接填 `http://127.0.0.1:8732/mcp` 就能连。

## 鉴权、状态码与完整部署说明

见 **`docs/HTTP-DEPLOY.md`**：启动器与开机自启、chroot 路径绑定、路由与帧的选择、
JSON-RPC → HTTP 状态码映射表、四个大小上限、token 鉴权（`APK_INDEX_MCP_TOKEN`，
非回环地址无 token 直接拒启）、`decompile` 的 `auto` 降级契约、curl 全流程、排障表。

三条最容易踩的先放在这里：

- 业务错误不占状态码：`tools/call` 成败都回 `200`，看信封里的 `ok` / `code`。
- `tools/call` 的 JSON-RPC `method` 恒为 `tools/call`，工具名在 `params.name`。
  把工具名当 method 发会得到 `404 / -32601`。
- `GET /mcp` 免鉴权，是健康检查；它不含任何包内容。

## HTTP 帧的选择

`Accept` 里同时有 `application/json` 与 `text/event-stream`（ktor/OkHttp 客户端的默认写法）时，
服务端回**裸 JSON**；只有客户端只接受 `text/event-stream` 才回 SSE 单帧（`event: message` + `data: <同一份 JSON>`）。
原因是有些客户端一进 SSE 模式就按"长流"读，单条响应要等流结束才交给上层，白吃一个 request timeout。
`--verbose` 会把每个请求的方法/工具名、字节数和超过 500ms 的耗时打到 stderr，
慢在哪个工具、有没有卡在锁上，看一眼日志就知道。

## 输出：人读文本 + 机器 JSON 双通道

`tools/call` 的结果给两份：

* `content[0].text` —— 给人读的渲染（`src/apkindex/render.py`）：一行结论 + 对齐条目 +
  一句下一步；空结果会解释"为什么可能是空"。descriptor / smali / reflector 这些
  干活要用的字段一个都不省，因为有的客户端只把 text 喂给模型。
* `structuredContent` —— 完整 envelope JSON，字段与早期版本一致，给程序解析。

以前两份内容都是同一坨 JSON，客户端常常重复显示两遍，人读很费劲；现在 text 走渲染，
JSON 只留一份。传输层不变：客户端 Accept 里同时允许 JSON 就回裸 JSON，只要 SSE 才回帧。

要自定义某个工具的样子：`render.RENDERERS["toolName"] = fn`（fn 收 envelope 返回字符串）；
没注册的工具自动走 `_r_generic`，至少是 key 行 + 编号条目，不会退回裸 JSON。
