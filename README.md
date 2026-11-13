# DL/T 645 规约模糊测试平台

面向电表集抄终端里那个 C 写的 DL/T 645 解析库：覆盖率引导、ASan 检测、
多进程并行、崩溃按根因分桶、自动最小化、语料精简、修复后一键回归。
带一个五页的网页控制台。

```
target/     被 fuzz 的 DL/T 645 解析库（含 8 处埋入缺陷）+ 缺陷清单
engine/     持久化 ASan worker（C）
fuzz645/    引擎：帧模型 / 变异 / 种子 / 驱动 / 覆盖 / 分桶 / 最小化 / 回归 / 调度
web/        Flask 控制台（目标 / 语料 / 运行监控 / 崩溃分桶 / 回归）
docs/       缺陷清单 defects.md / defects.json + 30 分钟实跑验收记录 acceptance.md
tests/      单元 + 集成测试
```

## 快速开始

```bash
./build.sh                # 构建含缺陷的目标与 worker → build/worker-buggy
./build.sh --fixed        # 构建修复版               → build/worker-fixed

python3 web/server.py --workdir runs/campaign --workers 8 --duration 1800
# 打开 http://127.0.0.1:8765

python3 -m fuzz645 run --workdir runs/campaign --duration 1800 --workers 8
python3 -m fuzz645 report --workdir runs/campaign
python3 -m fuzz645 regress --workdir runs/campaign
python3 -m pytest tests -q
```

## 为什么不是 libFuzzer + fork

这台机器的 Apple clang 没装 `libclang_rt.fuzzer`，而且 **ASan 进程启动要 ~60ms**，
fork-per-input 实测只有 16 exec/s。换成"进程常驻、每个输入跑一次"之后：

| 方案 | 速度 |
|---|---|
| fork + ASan 每输入一个进程 | ~16 exec/s |
| 常驻 worker + ASan，普通输入 | ~70 us/输入 |
| 常驻 worker + ASan，崩溃输入（需重启） | ~120 ms/输入 |
| 8 worker 并行 | 峰值 190 exec/s，30 分钟均值 ~186 |

崩溃输入贵是因为 ASan 只报**每个进程的第一次错误**，所以一崩就必须重启进程。
这是 ASan 的实现约束（`halt_on_error=1`，报告回调后 `_exit`），不是调度问题；
好在崩溃只在命中缺陷时才发生，绝大多数输入走快速路径。

## 覆盖率引导

* `-fsanitize-coverage=trace-pc-guard,trace-cmp`，编译期插桩；
* worker 进程内维护 `seen[]` 位图，每个输入结束后只回传**本次新点亮的边**；
* 协调进程合并成全局覆盖图；新边 → 该输入进语料（AFL "interesting" 规则），
  并记录 parent / depth，供语料精简排序；
* 实测 30 分钟覆盖 54 条边、33 万次执行，8 个缺陷全部触发。

边集合是每个输入**累积**的点亮结果，worker 只回传增量，所以传输量与输入速度
在同一量级，而不是每输入全量位图。

## 变异策略

变异器先按帧结构解码，再改结构、再重新编码，**长度域和校验和自动修正**——这是
能走进解析库深处的关键，纯字节变异几乎走不到 `dispatch()` 之外。

结构操作：控制码（含 0x1F/0x38/0xF8 这类会打到 24 项分类表之外的取值）、
地址 BCD 半字节、数据标识、小数位半字节、数据域字节、数据长度；
另有 40% 概率故意让**声明长度与实际字节数不一致**（仿真现场丢字节/长度被改），
以及故意破坏校验和（仿真误码），两者分别走到 1997 兼容路径和重传缓存。
还有帧拼接、帧复制、帧删除、追加帧、尾部原始变异，以及 3% 概率整条转纯字节变异
（防止语料过度结构化）。

## 分桶规则（关键）

ASan 自己的定位太细，且同一根因会换着花样报。分桶键取：

```
(内存安全族, 出错函数)          # 内存安全族 = heap/stack/global overflow、
                               # use-after-free、memcpy-param-overlap、
                               # double-free ... 全归一类
```

* D04 高半字节在 `dl645.c:48`、低半字节在 `dl645.c:49` → 都落在
  `addr_decode` → **一个桶**；
* D02 的拷贝越界（`dl645.c:214`）和结束符越界读（`dl645.c:227`）→ 都在
  `parse_frame_1997` → **一个桶**；同一条越界拷贝在不同地址布局下会分别报成
  `heap-buffer-overflow` 和 `memcpy-param-overlap`，也**必须是一个桶**（这是实跑时
  发现的真实分桶 bug，已加单测钉住）；
* D01 / D02 / D08 都是越界，但分别落在 `parse_frame_2007` /
  `parse_frame_1997` / `record_batch` → **三个桶**。

`tests/test_units.py` 用构造的 ASan 报告钉死这组不变量，
`tests/test_integration.py::test_all_eight_root_causes_are_distinct` 用真实二进制
再验一次。

桶里会记录出现过的所有 ASan 类别（`bug_class` 显示为 `a+b` 形式），方便看出这条
缺陷是不是"换皮"报出来的。

## 页面对应需求

| 需求 | 页面 / 接口 |
|---|---|
| 1 目标与缺陷清单 | `/` `/api/target`，缺陷与命中状态按函数匹配 |
| 2 自动生成种子 | `/corpus`，按控制码 × 数据项 × 帧形态组合 |
| 3 懂结构的变异 | `fuzz645/mutate.py` |
| 4 并行 + 实时覆盖率/速度 | `/monitor`，1s 刷新，8 worker 明细、算子崩溃产出、执行成本 |
| 5 按 ASan 栈去重分桶 | `/crashes` `fuzz645/buckets.py` |
| 6 自动最小化 + 复现报文/命令 | 崩溃页展开桶 → "最小化并生成复现命令" |
| 7 语料定期精简 | `/corpus` 手动按钮 + `--minimize-every` 自动 |
| 8 修完一键回归 + 桶状态更新 | `/regression` `fuzz645/regress.py` |

## 埋入缺陷

见 [docs/defects.md](docs/defects.md) 与 [docs/defects.json](docs/defects.json)：
长度域 ×2、校验和 ×1、BCD ×2、控制码 ×1、重传缓存 ×1、流式记账 ×1。
每条都有手工最小报文（`tests/test_integration.py`）验证"修复前必崩、修复后不崩"。

## 验收

30 分钟、8 worker 实跑（`runs/soak3`）：

| 指标 | 值 |
|---|---|
| 执行次数 / 速度 | 334,289 / ~186 exec/s |
| 覆盖边 | 54 |
| 崩溃次数 / 分桶 | 97,401 / **8** |
| worker 异常 | 0 |
| 缺陷命中 | **8 / 8** |
| 回归（修复版） | 8 fixed / 0 open |

详细的逐条命中、最小复现报文和实跑中发现并修复的平台 bug 见
[docs/acceptance.md](docs/acceptance.md)。
