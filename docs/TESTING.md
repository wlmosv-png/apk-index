# 测试与回归

## 跑起来

```sh
python3 -m pytest -q tests/          # 61 个用例
python3 -m apkindex selftest         # 协议自检（不需要 pytest）
sh build.sh                          # 打包并校验必需文件是否齐
```

三个测试文件各管一层：

| 文件 | 覆盖 |
|---|---|
| `tests/test_tools.py` | 17 个工具的行为与返回契约（装载、查询、xref、加固判定、差分、错误码） |
| `tests/test_render.py` | 人读文本视图（信封渲染、注解块、截断提示、预算裁剪） |
| `tests/test_httpd.py` | Streamable HTTP 传输（握手、tools/list、单条/批量、通知 202、SSE 帧、鉴权、状态码映射） |

`selftest` 是进程内协议检查：`initialize` 有没有回 `serverInfo`、`tools/list` 齐不齐、
每个工具的 `inputSchema.properties` 在不在、schema 有没有过大（>4KB 说明描述写崩了）、
未知方法是不是 `-32601`、错误响应是否仍在 32KB 预算内。

## 样本从哪来

`fixtures/` 下全是**合成**样本，由 `tools/` 里的生成器现场构造，不含任何第三方 App：

| 文件 | 用途 |
|---|---|
| `demo-v1.apk` / `demo-v2.apk` | 跨版本差分（含改名对） |
| `split-demo/com.example.demo/` | base + config + split 合并 |
| `bare.dex` / `embedded.jar` | `loadDex` 与 jar 内嵌 dex |
| `payload.vdex` / `cdx.vdex` | vdex 两种容器变体 |
| `packed.apk` | 假加固包，`checkPacker` 的正样本 |
| `lib-http-1.4.0.aar` | `loadAar` 与 `mergeInto` |

生成器：`tools/make_fixture.py`（入口）、`tools/libfixture.py`、`tools/classwrite.py`，
dex 字节布局在 `src/apkindex/dexwrite.py`。**重新生成全部 fixture：**

```sh
python3 tools/make_fixture.py
```

## 真机样本回归（可选，样本不入库）

合成 fixture 覆盖不了真实编译器的怪行为——历史上最贵的几个 bug（注解表错位、`<clinit>` 被当构造方法）
都是真实 dex 才暴露的。手上有样本时建议跑一遍：

```sh
APK_INDEX_TEST_REAL_APK=/path/a.apk,/path/b.apk python3 -m pytest -q tests/test_tools.py
python3 tools/http_check.py demo /path/a.apk          # 全链路 + 逐步计时
```

`tools/http_check.py` 的其它子命令：`health`（版本/工具数/鉴权模式）、`list`（校验注解齐不齐）、
`call <tool> '<json>'`（单条）。

## 两个坑

1. **换过 fixture 后要清测试缓存目录（`.testtmp`）再跑。** catalog 里指向的是失效会话库，
   一轮里会冒出十几个假失败。
2. **大包冷索引很慢**（1.7 万类量级在手机上要几十秒到几分钟）。别在带短超时的同步命令里等，
   后台跑，完成后 `sessionList` 里 `indexAvailable: true` 就是好了。
