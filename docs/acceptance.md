# 验收记录

运行目录 `runs/soak3`，8 worker，1800 s，种子 645。
机器：Apple clang 21 / macOS 27 / arm64，14 核。命令：

```bash
./build.sh && ./build.sh --fixed
python3 -m fuzz645 run --workdir runs/soak3 --duration 1800 --workers 8 \
        --minimize-every 180
```

## 结果

| 指标 | 值 |
|------|-----|
| 实际时长 | 1800 s（+ 后台最小化收尾） |
| 执行次数 | 334,289 |
| 平均速度 | ~186 exec/s（8 worker） |
| 覆盖边 | 54 |
| 崩溃次数 | 97,401 |
| 崩溃分桶 | **8** |
| worker 异常 | **0** |
| 语料 | 22 → 精简后 17（覆盖 54 → 54，不降） |
| 存储 | 23 MB |

## 缺陷命中（8/8）

| 缺陷 | 函数 | 桶 | 崩溃次数 | 最小复现 | 修复版 |
|------|------|-----|---------:|---------:|--------|
| D04 BCD 地址表 | `addr_decode` | `global-buffer-overflow dl645.c:48` | 62,650 | 8 B | 不崩 |
| D06 控制码表 | `dispatch` | `global-buffer-overflow dl645.c:85` | 18,516 | 12 B | 不崩 |
| D03 校验和策略表 | `checksum_retry` | `global-buffer-overflow dl645.c:138` | 6,245 | 60 B | 不崩 |
| D05 小数位倍率表 | `dispatch_item` | `global-buffer-overflow dl645.c:113` | 5,307 | 16 B | 不崩 |
| D01 2007 长度域 | `parse_frame_2007` | `stack-buffer-overflow dl645.c:164` | 4,178 | 211 B | 不崩 |
| D02 1997 双字节长度 | `parse_frame_1997` | `heap-buffer-overflow dl645.c:214` | 331 | 13 B | 不崩 |
| D07 重传缓存 | `retransmit_cache` | `heap-use-after-free dl645.c:303` | 132 | 58 B | 不崩 |
| D08 批处理窗口 | `record_batch` | `heap-buffer-overflow dl645.c:320` | 41 | 48 B | 不崩 |

桶数 = 根因数 = 8，没有一条根因被拆成多个桶，也没有两条根因被并成一个桶。

## 一键回归

`/regression` → "对修复版一键回归"：

```
fixed  global-buffer-overflow dl645.c:48
fixed  global-buffer-overflow dl645.c:85
fixed  heap-buffer-overflow   dl645.c:320
fixed  global-buffer-overflow dl645.c:138
fixed  global-buffer-overflow dl645.c:113
fixed  stack-buffer-overflow  dl645.c:164
fixed  heap-buffer-overflow   dl645.c:214
fixed  heap-use-after-free    dl645.c:303
8 fixed / 0 open
```

对**未修复**的旧二进制重放同一批复现报文，8 个桶全部保持 `open`（反向验证，
见 `tests/test_integration.py::test_unfixed_build_keeps_buckets_open`）。

## 覆盖时间线

前 3 分钟 8 个桶就全部出现（D07、D08 最晚，分别需要"先合法帧再坏帧"和
"单输入 5 帧以上"两个条件）；之后 27 分钟主要在加深每个桶的输入多样性，
边覆盖稳定在 54。

## 实跑中发现并修复的问题

平台自身也通过这次 30 分钟运行暴露了三个 bug，均已修复并加了回归测试：

1. **空输入导致变异器抛异常** → 一个 worker 线程静默退出，运行显示"进行中"
   但 0 exec/s。修复：`mutate_raw` 处理空 buffer；worker 线程改为逐次容错，
   任何异常只损失一个输入并计入 `worker 异常`。
2. **崩溃 id 并发冲突** → 两个 worker 同时命中同一输入时 `UNIQUE constraint`
   异常。修复：碰撞重试 + 并发单测。
3. **同根因拆桶** → 同一条越界拷贝在不同地址布局下分别报
   `heap-buffer-overflow` 和 `memcpy-param-overlap`，被分成两个桶。
   修复：内存安全类错误归并为同一族再与函数组合。
