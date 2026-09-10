# 变更

## 0.4.4 — 注解进得来、查得到（schema 6）

真机样本回归（17.9MB / 3 dex / 26695 类）暴露：注解表里全是错位垃圾。

- **dex 注解按现行布局解析**：`annotation_item = ubyte visibility + encoded_annotation`
  （visibility 写在 `encoded_annotation` 内部是早年 spec 的写法，d8 不这么发）。旧读法把
  code 区字节当元素值收了进来——单条 `args_json` 最大 4MB，索引从 122MB 虚胖到 707MB。
  同一个包现在 **140MB / 46s**，注解 86591 行、`args_json` 合计 8.3MB、单条最大 3349B，
  visibility 只剩 0/1/2，非 reference 描述符 0 条。
- **注解集合项偏移按 uint 读**：`annotation_set_item.size` 与 `annotation_off_item` 都是
  `uint`，不是 uleb128；错位会让整类注解解析失败。
- **`encoded_value` 的 float/double 宽度夹住**：宽度字段越界以前会炸 `struct.pack("<I")`，
  连带丢弃整类注解；现在仍按 size 前进、只取低 4/8 字节。
- **单条注解读失败不再拖垮整类**，并在 `parseNotes` 报“跳过 N 条”，不静默降级。
- **`getSignature` 带注解**：类级 `signature.class.annotations`、方法级 `items[].annotations`，
  每条 `descriptor / javaName / visibility(build|runtime|system)` + 元素值（超长是 sha1 摘要，
  带 `valuesClipped`）。
- **`searchClasses` 新增 `annotatedWith`**：`@Keep` / `dalvik.annotation.Keep` /
  `Ldalvik/annotation/Keep;` 都认；只给简单名时按 `%/Name;` 后缀匹配。用来在混淆包里挑
  名字稳定的锚点，或分辨哪些类是 Kotlin（`@Metadata`）。空白值明确报 BAD_ARGUMENT。
- **`getSignature` 文本视图修复**：不带 `member` 时以前只印“0 个匹配”，四种写法与注解全在
  `signature` 里没出来；现在印类级块（class/reflector/classForName/smali/parent/注解）。
- **缓存位置钉死**：`APK_INDEX_CACHE` 以前随 cwd 漂移（仓库 `.cache` 与 `/root/.cache` 都
  出现过，索引散两处、空间统计失真）。启动器钉到 `$APK_INDEX_CACHE`。
- **`force=true` 真的重建**：以前同 sha + schema 匹配时 force 直接命中旧索引返回，改了索引
  代码却拿旧数据，看起来像“修了没用”。
- **`dexwrite` 写注解同步为现行布局**（visibility 提前、集合偏移 uint），fixture 与读端
  端到端闭环。自测 **60**（tools 32 + render 10 + httpd 18）。
- 自测坑：换 fixture 后要清 `.testtmp` 再跑，否则 catalog 指向失效会话库，一轮里会冒出
  十几个假失败；清空后连续两轮 32/32。
- 顺带更正一条旧结论：`checkPacker` 并没有“dex 数 ≥2 就算加固”的规则，真样本被判加固是
  旧索引里那坨错位注解导致的。重建后：真实 App=否(none)、合成壳样本=是(high)。
## 0.4.3
- **加**：`tools/list` 每个工具都带 `annotations` 与 `outputSchema`。四个注解按名字
  锁死并进回归测试：只有 `unload` 是 `destructiveHint`（删的是自己的索引缓存），
  `loadApk/loadAar/loadDex` 是"会写缓存但非破坏"，其余 13 个只读。
  客户端据此做自动放行，不用再靠"看起来是查询"猜。
- **加**：`decompile` 默认 `format=auto` —— jadx → baksmali → 索引重建视图逐级退，
  任何环境都带回正文，并在 `items[0].chain` 里写清每一步为什么退。
  以前 jadx 不在就直接 `DECOMPILER_UNAVAILABLE`，客户端空手而归。
- **加**：HTTP 可选 token 鉴权（`APK_INDEX_MCP_TOKEN` / `APK_INDEX_TOKEN`）。
  `Authorization: Bearer` 或 `X-Apk-Index-Token`，`hmac.compare_digest` 比较，
  不通过时 `401` + JSON-RPC `-32002` + `WWW-Authenticate`，**body 不解析**；
  `GET /mcp` 健康检查免鉴权（启动器要靠它探活）。非回环地址且无 token 直接拒启。
- **修**：信封单条上限会削掉 `decompile` 的 `note`/`chain`/`engine`（正文超 2 KiB 时
  先删元数据、留正文，方向刚好错）。现在单条响应不套每条上限，多条时先削正文；
  整体仍由 32 KiB 上限兜。
- **修**：`render` 层 `decompile` 从信封顶层读字段，而正文与引擎信息在 `items[0]`
  → 真实调用永远显示"没有代码正文"。现在按 items[0] 读，并分行显示引擎/降级链/说明。
- **修**：`<clinit>` 被当成构造方法。d8/R8 给静态初始化器也打 `kAccConstructor(0x10000)`，
  按位判 `is_constructor` 就会让 `matchSignature` 生成 `constructors { ... }` 去 hook
  方法表里不存在的位置 —— 代码能编译、运行期静默不命中。现在判据是 `name == "<init>"`，
  修饰符词表按名字校正（`<clinit>` → `static-initializer`），DSL 对 `<clinit>` 直接给出
  说明与两条可行路子而不是假 matcher。`SCHEMA_VERSION` 3→4：旧库存的值是错的，
  加载时按 INDEX_STALE 拒用，`loadApk(force=true)` 重建。真机样本暴露。
- **加**：`tools/http_check.py`：HTTP 传输的自检客户端（health / list 校注解 /
  call 单条 / demo 真机样本全链路带计时）。
- **文**：新增 `docs/HTTP-DEPLOY.md`（路由与帧的选择、状态码映射表、上限表、
  鉴权、降级契约、curl 全流程、排障表）。名字防呆自测 `t_name_integrity` 现在
  连 `docs/*.md` 一起校（工具名、cli 子命令、仓库内文件路径）。
- **测**：29 + 16 + 9。新增鉴权 6 例与契约 2 例。

## 0.4.2
- **加**：Streamable HTTP 传输（`apkindex.httpd`）。与 stdio 共用 `Server.handle()`，
  协议行为、工具集、返回信封一致；默认只绑 127.0.0.1。
- **加**：`initialize` 回 `Mcp-Session-Id` / `MCP-Protocol-Version` 头，只发不校验
  （`sessionMode: stateless`），严格拒绝未知会话 id 会把实现松的客户端卡死。
- **加**：按客户端 Accept 选帧 —— 两边都接受就回裸 JSON（ktor-client 进了 SSE
  就切"等流结束"的读法，实测会白等一个超时）。
- **加**：JSON-RPC 错误码 → HTTP 状态码集中映射（400/404/500），批量里只要有一条
  成功就 overall 200；body 超限先读干净再回 413，否则客户端只看到 broken pipe。
- **加**：意外异常兜底回 500 带原因，不再静默断连。
- **加**：`tools/httpd-android.sh` 启动器（幂等：绑定三条宿主路径进 chroot、
  按 cmdline 杀旧、`setsid` 起新、探活）+ `<SERVICE.D>/` 开机自启。
- **修**：`verbose` 下打印请求头摘要与慢请求耗时，网关类问题能一眼对上。

## 0.4.1
- **修**：写库消毒下沉到 `_bulk`/`refs`/`annotations`/`meta` 全部咽喉（第三方 App 的
  lone surrogate 会让整条索引 `UnicodeEncodeError` 崩掉）；消毒结果改为标准 `U+FFFD`。
- **修**：会话库打开前 `PRAGMA quick_check`，坏库自动删除重建 —— 之前崩溃留下的半截库
  会因为按 sha 去重被反复复用，那个包就永久索引不了。
- **修**：`backend` 的 schema 一直 advertised `auto` 但代码拒收 → `auto` 现在真的是
  "按 APK_INDEX_BACKEND 选默认后端"。loadApk 的 enum 也补齐。
- **修**：`cli pull` 调的是不存在的 `devicePullApk`（等于一直坏的），改走 `loadApk(fromDevice)`；
  `doctor` 收尾调的不存在的 `closeSession` 改成 `unload`。
- **加**：防呆自测 `t_name_integrity`（源码/README 引用的工具名、子命令、文件路径必须真实存在）、
  坏库自愈、lone surrogate 消毒、`backend=auto` 共 4 条；22 条自测。
- **加**：`tools/apkidx.sh` —— 一次调一个工具的封装（`sid`/`call`/`env`/`selftest`/`doctor`）。
- **改**：README 里编造的 `cli search/xref/probe --apk` 用法与 `tools/adb-load.sh` 全部删掉。

## 0.4.0
- 修：`cli pull` 之前调了根本不存在的工具 `devicePullApk`（永远失败）；改走真实入口
  `loadApk(fromDevice=true, packageName=...)`。`doctor` 清场改用真实存在的 `unload`。
- 修：README 的 cli 用法块写了不存在的子命令（search/xref/probe --apk）；真实只有
  tools/call/pull/doctor/sessions。此前还编过三个不存在的 tools/adb-*.py，一并清除。
- 加：防呆自测 `t_name_integrity` —— 源码里 `call_tool("X")` 的 X、README 写的 cli 子命令、
  README 引用的仓库文件路径，全部必须真实存在，缺一项直接红。
- 加：`tools/apkidx.sh` 统一入口（env/tools/selftest/call/sid/pull/doctor），随包发布。
- 版本：`config.VERSION` 0.1.0 -> 0.4.0，与 pyproject/CHANGELOG 对齐。
- 修：`probe` 现在真的处理 `target`/`maxDepth`（此前被 `**_` 吞掉：schema 与行为不符）。
  类目标走 `xref` 的整类语义，成员目标 `A#m(sig)` / `A->m(sig)` 两种写法都试；
  深挖失败另放 `xrefErrors`，不再把整次 probe 打死。probe 的 schema 补上这两个参数。
- 修：`probe` 的 `implementations` 分节恢复（"X 有哪些实现类"这类问法此前只给候选不给答案）。
- 修：`matchSignature(packagePrefix=...)` 同时匹配 `com/example/demo` 与 `com.example.demo`
  两种存法（只按点号 LIKE 会让"看着对"的前缀静默返回 0）。参数个数上限 3 → 8。
- 修：`xref` 裸类名 = 该类全部成员的引用；`NOT_FOUND` 时把原样入参带回消息里。
- 修：`cli.py` 里一处 `from . import env` 让命令行整体 ImportError；缓存目录改用
  `getattr(cfg, "CACHE_DIR", ...)` 兜底。
- 修：`decompile` 三档兜底（SMALI → JAVA+SMALI → SMALI）标注 `backend`/`format`/`truncated`。
- 测试：19 组全通过（含真机 APK 校准）。用例顺序耦合写进注释——`diffSessions` 的改名配对
  必须在被 `loadAar(mergeInto=...)` 污染之前的干净会话上验。
- 文档：README 新增「参数与行为速查」，条目全部对齐 `tools/list` 实测输出。
