# apk-index

本地跑的 **APK / AAR / DEX 结构索引 + MCP Server**。17 个工具，纯 Python 标准库，零运行时依赖。

给它一个安装包，它把类、方法、字段、字符串常量、注解、继承关系、调用引用全部落进一个可查询的
SQLite 会话；之后你问的都是真答案，而不是"印象里这个库里应该有"。

面向的活：给 Android 应用写 LSPosed/Xposed 模块、逆向排查、版本对比、判断有没有被加固。

```text
写 hook 之前你必然问过自己：这个包里到底有没有 X？
apk-index 把这个问题变成一次查询，并且给得出证据。
```

---

## 为什么需要它

写 hook 代码最容易犯的错，是把"我以为"当成"包里是这样"。类名猜错、重载签名写错、
`<clinit>` 当构造方法挂上去（编译得过、运行期静默不命中）、目标是加固的所以静态结构全是壳代码
—— 这些错误的共同点是：**成本后置**。你写完、装上、什么都不发生，才发现少查了一步。

apk-index 的作用是把这一步前置成一次可验证的查询。所有回答都带 `total`（全量命中数）和
`hint`（截断、降级、参数写错的提示），空结果必须能解释自己为什么是空的。

## 特性

- **零依赖**：只需要 `python3 >= 3.11`。不需要 pip 装任何包，不需要 root、不需要联网。
  装了 `jadx` / `baksmali` 会自动升级反编译质量，没装就逐级降级，**绝不空手返回**。
- **真索引，不是字符串搜索**：逐 dex 解析，方法体里的字符串常量、字段引用、方法引用一起入库，
  所以能问"这句文案在哪个方法里""谁调用了这个方法"。
- **注解可读**：类和方法上的注解带 descriptor、可见性（build/runtime/system）和元素值。
  找未混淆锚点用 `@Keep`，判断是不是 Kotlin 用 `@Metadata`。
- **加固判定**：stub 入口类、壳特征库、类数量与字符串熵，给证据链和结论。判成加固时
  会直接告诉你静态 hook 无意义，先解壳。
- **版本可对比**：两个会话之间做漂移匹配，回答"这版改了啥、那些改名是混淆还是真重构"。
- **缓存复用**：同一 sha256 二次装载直接命中，不重建（一万多类的包省掉几十秒）。
- **响应有硬预算**：单条 2KB、整包 32KB，超长值摘要化。给 LLM 当工具用不会被撑爆。
- **两种传输**：stdio（客户端能自己拉进程）与 Streamable HTTP（客户端只能填一个 URL）。
  协议行为、工具集、返回信封完全一致。

## 安装

```sh
git clone https://github.com/wlmosv-png/apk-index.git
cd apk-index
python3 -m apkindex version          # 仓库内直接跑，不用装
```

装成命令（可选）：

```sh
pip install -e .            # 得到 apk-index
apk-index version
apk-index env               # 看 allowedRoots / 缓存位置 / 可用的反编译引擎与后端
```

不装任何东西也能用全部功能：`sh tools/apkidx.sh <子命令>`。

## 五分钟上手

```sh
cd apk-index
# 1. 索引一个包（base + split 自动合并），拿 sessionId
python3 -m apkindex call loadApk '{"path":"/path/to/target.apk"}'

# 2. 看规模和加固判定
python3 -m apkindex call stats       '{"sessionId":"target"}'
python3 -m apkindex call checkPacker '{"sessionId":"target"}'

# 3. 定位目标：按名字、按注解、按文案
python3 -m apkindex call searchClasses   '{"sessionId":"target","query":"Login","packageFilter":"com.example"}'
python3 -m apkindex call searchClasses   '{"sessionId":"target","query":"com.example","annotatedWith":"@Keep"}'
python3 -m apkindex call searchByString  '{"sessionId":"target","text":"登录中","minLen":2}'

# 4. 要 hook 起手块：四种写法 + 注解，直接抄
python3 -m apkindex call getSignature  '{"sessionId":"target","class":"com.example.LoginActivity","member":"doLogin"}'

# 5. 看实现体和调用链
python3 -m apkindex call decompile '{"sessionId":"target","target":"com.example.LoginActivity#doLogin()V","maxLines":200}'
python3 -m apkindex call xref      '{"sessionId":"target","method":"com.example.LoginActivity#doLogin()V","direction":"callers","depth":2}'
```

`sessionId` 接受完整 id、**唯一前缀或包名**，不用复制粘贴 `ses_...`。

一步都懒得组织的时候，用编排工具：

```sh
python3 -m apkindex call probe '{"sessionId":"target","question":"想拦截登录按钮的回调"}'
```

---

## 当 MCP Server 用

### stdio（客户端能自己拉起进程）

```json
{
  "mcpServers": {
    "apk-index": {
      "command": "python3",
      "args": ["-m", "apkindex"],
      "cwd": "/path/to/apk-index",
      "env": { "PYTHONPATH": "/path/to/apk-index/src" }
    }
  }
}
```

装成包之后把 `command`/`args` 换成 `["apk-index"]` 即可。

### Streamable HTTP（客户端只能填 URL）

```sh
python3 -m apkindex.cli serve-http --host 127.0.0.1 --port 8732
```

端点 `http://127.0.0.1:8732/mcp`，stateless，`initialize` 之后不用带 session 头。
在 Android 设备上常驻的部署办法（chroot 路径绑定、开机自启的例子）见
**`docs/HTTP-DEPLOY.md`** 与 `tools/httpd-android.sh`。

要开鉴权：设 `APK_INDEX_MCP_TOKEN`，客户端带 `Authorization: Bearer <token>` 或 `?token=`。
`GET /mcp` 健康检查故意不需要 token，方便启动器探活。

## 17 个工具

| 组 | 工具 | 必填 | 常用参数 |
|---|---|---|---|
| 装载 | `loadApk` | `path` | `splits` `maxApkBytes` `force` `fromDevice` `packageName` `backend` |
| | `loadAar` | `path` | `mergeInto` `backend` |
| | `loadDex` | `path` | `sessionId` `format` `source` |
| 会话 | `sessionList` | — | — |
| | `unload` | `sessionId` | `keepFiles` |
| | `stats` | `sessionId` | — |
| 结构 | `searchClasses` | `sessionId` `query` | `kind` `scope` `packageFilter` `annotatedWith` `limit` |
| | `listMembers` | `sessionId` `class` | `include` `namePattern` `withStrings` |
| | `getSignature` | `sessionId` `class` | `member` `scope` |
| | `findImplementations` | `sessionId` + `interface`/`superClass`/`method` | `transitive` `includeAbstract` |
| | `matchSignature` | `sessionId` `signature` | `params` `returnType` `modifiers` `referredStrings` `accessedFields` `invokedMethods` `namePattern` `packagePrefix` `requireConstructor` `minScore` |
| 内容 | `searchByString` | `sessionId` `text` | `match` `scope` `methodLimit` `minLen` |
| | `xref` | `sessionId` `method` | `direction` `depth` |
| | `decompile` | `sessionId` `target` | `format` `maxLines` |
| 版本 | `diffSessions` | `sessionA` `sessionB` | — |
| 判定 | `checkPacker` | `sessionId` | — |
| 编排 | `probe` | `sessionId` `question` | `target` `maxDepth` `limit` |

完整 schema 以运行时为准（这张表会落后于代码）：

```sh
python3 -m apkindex tools        # 全量 inputSchema + annotations + outputSchema
```

用熟了会省时间的几个点：

- **`scope`**：`app`＝目标自身代码，`library`＝注入进来的库，`system`＝框架与 rom，`all`（默认）。
  查混淆目标先收紧成 `app`，否则 `kotlin.*` 的噪声会淹没结果。
- **`kind`**：`prefix`（默认）/ `exact` / `regex`。前缀查不到别急着下"不存在"的结论，换 `regex` 再试。
- **`member` 留空**＝只看类级签名（含类上的注解）；给了成员名才附带方法体字符串与方法注解。
  构造方法是 `<init>`，静态初始化器是 `<clinit>`。
- **`annotatedWith`**：`@Keep` / `dalvik.annotation.Keep` / `Ldalvik/annotation/Keep;` 三种写法都认。
  只命中类级注解；方法上的注解走 `getSignature`。
- **`matchSignature`** 是结构相似度：混淆之后名字靠不住，用"参数形状 + 引用的字符串 + 修饰符"捞目标，
  位置通配写 `"any"`。
- **`decompile` 的 `format=auto`** 是刻意的：jadx → baksmali → 索引重建视图逐级降级，
  最差也给你一份能读的 outline，而不是报错。

## 返回契约

```json
{"ok": true, "items": [], "total": 132, "hint": "...", "ms": 41}
```

- `total` 是**全量命中数**，`items` 只是当页（默认 50，硬上限 200）。被截断一定写在 `hint` 里。
- 单条超过 2KB 会被摘要化（例：`@Metadata` 的超长 `d1` 换成 `{"_blob":53,"_sha1":"..."}`），
  整包响应硬上限 32KB。**要原文走 `decompile`**，别在注解字段上较真。
- 每个工具都声明 `annotations`（`readOnlyHint` / `destructiveHint` / `idempotentHint` /
  `openWorldHint`）。只有 `unload` 是破坏性的，删的是自己的索引缓存。客户端可以据此放行，
  不用靠"看起来像查询"来猜。
- 参数名写错会直接报 `BAD_ARGUMENT` 并列出有效参数。以前会静默丢参、返回假的 `total=0`
  —— 那种"假空结果"比崩溃害人得多。

### 错误码

| 码 | 含义与对策 |
|---|---|
| `BAD_ARGUMENT` | 参数名/正则/枚举不合法，响应里带有效参数清单 |
| `SESSION_NOT_FOUND` | sessionId 不存在或前缀不唯一，先 `sessionList` |
| `APK_TOO_LARGE` | 超过 `maxApkBytes`；调大，或用 `loadDex` 只导需要的那几个 dex |
| `UNSUPPORTED_FORMAT` | 加固体里的内嵌 dex 读不动：先 apktool / `uncompress_dex` / `vdexExtract` 提出来，再 `loadDex` |
| `PATH_NOT_ALLOWED` | 路径不在 `APK_INDEX_ALLOWED_ROOTS` 白名单内 |
| `INDEX_STALE` | 索引 schema 版本落后（老库存的值可能是错的），`loadApk(force=true)` 重建 |

## 配置

| 环境变量 | 作用 |
|---|---|
| `APK_INDEX_CACHE` | 索引落盘位置。**建议显式设**，不设时解析顺序会随 cwd 漂 |
| `APK_INDEX_ALLOWED_ROOTS` | 可读根目录白名单（`:` 分隔）。默认放开 `/data/local/tmp`、`/sdcard` 等常见位置 |
| `APK_INDEX_MCP_TOKEN` / `APK_INDEX_TOKEN` | 开 HTTP 鉴权 |
| `APK_INDEX_BACKEND` | `auto`（默认）/ `builtin` / `androguard` / `dexlib2` |
| `APK_INDEX_JADX_HOME` | 装了就出 Java 反编译视图 |
| `APK_INDEX_BAKSMALI_JAR` / `APK_INDEX_DEXLIB2_JAR` | 装了就出真 smali |
| `ADB` | `loadApk(fromDevice=true)` 用哪条 adb |

```sh
python3 -m apkindex env          # 当前生效的 roots / 缓存 / 引擎 / 后端
python3 -m apkindex.cli doctor
```

`doctor` 报 `ok: false` 只代表**可选**依赖缺失（aapt2 / baksmali / dexlib2 / apktool），
索引与结构化查询不受影响。

## 三个常见任务

**改 UI 文案，找到该挂的回调**

```sh
searchByString  {"sessionId":"t","text":"登录中","minLen":2}
getSignature    {"sessionId":"t","class":"<上一步的类>","member":"<方法>"}
decompile       {"sessionId":"t","target":"<类#方法(sig)>","maxLines":400}
```

**目标是混淆的，按结构而不是名字找**

```sh
matchSignature  {"sessionId":"t","signature":"Lx/a;->b(Landroid/content/Context;)V",
                 "modifiers":["static"],"referredStrings":["token"],"minScore":0.6}
diffSessions    {"sessionA":"旧版","sessionB":"新版"}
```

**动手前先判加固**

```sh
loadApk → checkPacker →（packed=true 就先解壳，拿到内嵌 dex 再 loadDex）
```

判成 `packed: true` 时**停手**。那时候选里全是壳代码，写进去的 hook 永远不执行。

## 测试

```sh
cd apk-index
python3 -m pytest -q tests/            # 61 个用例（tools 33 + render 10 + httpd 18）
python3 -m apkindex selftest           # 协议自检：握手、工具表、真实调用、错误预算
```

测试只依赖 `fixtures/` 下的**合成**样本（自己写的 dex 生成器造出来的，含一个假壳包），
不联网、不需要真机、不需要任何第三方 App。

手上有真实样本想做回归（可选，不入库）：

```sh
APK_INDEX_TEST_REAL_APK=/path/a.apk,/path/b.apk python3 -m pytest -q tests/test_tools.py
```

细节见 `docs/TESTING.md`。

## 目录结构

```text
src/apkindex/
  apkio.py      APK/zip 与 split 合并          axml.py     二进制 manifest 解码
  dex.py        dex 结构解析（含注解表）        dexwrite.py 合成 dex（测试与 fixture 用）
  index.py      SQLite 会话库、schema 与自愈    loaders.py  loadApk/Aar/Dex 主流程
  queries.py    17 个工具的实现                 render.py   人读文本视图
  signature.py  各种写法互转（Reflector/smali/Java/descriptor）
  dsl.py        模块侧 DSL 生成（hook 起手块）  packer.py   加固判定
  decomp.py     反编译引擎调度与降级            backends.py 索引后端选择
  envelope.py   返回信封与预算裁剪              httpd.py    Streamable HTTP 传输
  server.py     工具表与 dispatch               cli.py      命令行
tests/          单元 + 协议 + 渲染回归          fixtures/   合成样本（含假壳包）
tools/          自检客户端、fixture 生成器、Android 部署例子
docs/           HTTP-DEPLOY.md  传输契约与状态码  TESTING.md  测试与样本回归
```

## 边界

- 只索引**你有权分析**的文件。工具不做解密、不做脱壳、不绕过任何保护；遇到加固只会告诉你
  "静态结构不可信"，解壳是你自己的事。
- 全程离线。除了 `loadApk(fromDevice=true)` 会调你本机的 adb，代码里没有任何网络出站。
- 不修改被分析的文件。唯一写入的是自己的 SQLite 缓存目录。
- 加固体内的内嵌 dex 需要你先自己提出来（错误码里给了三条路子）。
- 索引是按包名+sha256 缓存的结构数据。要清干净：`unload` 或直接删缓存目录。

## 版本

当前 `0.4.4`，索引 schema 版本 6（旧库会被 `INDEX_STALE` 拒用，重建即可）。
变更历史见 **`CHANGELOG.md`** —— 里面记了不少 dex 布局上的坑，做类似解析的话值得读。

## 许可

MIT。见 `LICENSE` 与 `AUTHORS`。
