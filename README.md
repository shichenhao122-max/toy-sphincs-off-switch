# Mini-SPHINCS+ Off-Switch（教学玩具）

> **安全警告：本项目故意使用极小参数和简化编码，只用于学习与 RTL 架构推演。它不是 SPHINCS+ / SLH-DSA 的合规实现，绝不能用于真实密钥、授权或生产安全。**

这个目录实现了一个从哈希链到 Off-Switch license 的最小闭环：

1. WOTS+：把消息摘要的 base-w 数字映射为多条单向哈希链。
2. Merkle/XMSS：把 WOTS+ 公钥压缩成叶子，并用认证路径连接到固定根。
3. FORS：从多个小树中按消息摘要选择秘密值，重建一个 FORS 公钥。
4. Mini-SPHINCS+：FORS 公钥由 WOTS+ 签名，再由一层 XMSS 树认证；签名时不修改私钥状态。
5. Off-Switch：license 绑定 `chip_id + nonce + allowance`，成功后增加 allowance 并轮换 nonce。
6. License aggregation：四个芯片共享一个 Mini-SPHINCS+ 根签名，每个芯片只携带 ID、nonce 和 license 三条 Merkle 认证路径。
7. Signature streaming：签名可按任意字节宽度分块，模拟 RTL 的 ready/valid 流式入口。

## 立即运行

Windows PowerShell：

```powershell
cd E:\MARS\Off_switch\toy-sphincs-off-switch
python -m unittest discover -s tests -v
python -m examples.demo
```

也可以运行：

```powershell
.\run_tests.ps1
.\run_demo.ps1
```

项目只使用 Python 标准库，要求 Python 3.10 或更高版本。

## 玩具参数

| 参数 | 玩具值 | SPHINCS+/SLH-DSA 中的作用 |
|---|---:|---|
| `n` | 4 字节 | 哈希节点和安全参数长度；这里只相当于最多 32 位，完全不安全 |
| `w` | 4 | Winternitz 基数 |
| WOTS+ `len` | 19 | 每个 WOTS+ 签名中的链元素数量 |
| FORS | 3 棵、每棵高 2 | 从摘要中抽取 3 个索引 |
| XMSS 高度 | 2 | 只有 4 个 WOTS+ 叶子，会频繁复用，仅适合演示 |
| 签名长度 | 124 字节 | `R || SIG_FORS || SIG_WOTS || AUTH_XMSS` |

真实的 SPHINCS+-128s / SLH-DSA-SHA2-128s 使用 `n=16`、更高的超树和 14 棵更大的 FORS 树；签名为 7,856 字节。这里的 124 字节来自不安全的小参数，不能据此评估真实面积、带宽或安全性。

## 签名数据流

```text
message + optrand
        |
        v
  R, H_msg(R, PK, message)
        |
        +--> FORS indices --> selected secrets + auth paths --> FORS public key
                                                            |
                                                            v
                                               WOTS+ signs FORS public key
                                                            |
                                                            v
                                         XMSS auth path --> public root
```

验证器只持有 `(PK.seed, PK.root)`。它从签名和消息重建 FORS 公钥、WOTS+ 公钥、XMSS 叶子和最终根；最终根与 `PK.root` 相等才接受。

“无状态”指签名函数不维护 RFC 8554 中那种必须单调递增的 `q`。本玩具的 `ToySecretKey` 是不可变数据，两次签名不会更新它。真实 SPHINCS+/SLH-DSA 依靠大参数和安全分析控制随机选中同一 few-time key 的风险；本玩具的小树没有这种保证。

## Off-Switch 流程

直接 license：

```text
authority signs(domain || chip_id || current_nonce || allowance)
    -> device verifies
    -> allowance += signed amount
    -> nonce rotates immediately
    -> replay of the old license fails
```

聚合 license：

```text
ID leaves       -> id_root       --\
nonce leaves    -> nonce_root       +-> authority signs one aggregate message
H(ID_i, root)   -> license_root  --/

each device receives:
  shared signature + its ID path + nonce path + license path
```

聚合消息同时签入 `leaf_count` 和 `allowance`，避免只签根而没有树规模/授权量语义。每个叶子也编码位置，防止简单重排。

## 代码导航

- `toy_sphincs/params.py`：所有极小参数与签名长度公式。
- `toy_sphincs/utils.py`：域分离哈希、整数编码、摘要位字段解析。
- `toy_sphincs/merkle.py`：树构造、认证路径与从路径恢复根。
- `toy_sphincs/wots.py`：base-w、checksum、哈希链、签名和公钥恢复。
- `toy_sphincs/fors.py`：FORS 秘密值、树、签名和公钥恢复。
- `toy_sphincs/sphincs.py`：Mini-SPHINCS+ keygen/sign/verify 与流式序列化。
- `toy_sphincs/off_switch.py`：nonce、allowance、重放防护和门控工作负载。
- `toy_sphincs/aggregation.py`：Chip-ID/nonce/license 三棵聚合树。
- `tests/test_toy.py`：正确签名、篡改、错误消息、无状态、流式、重放、错芯片、错 nonce 和聚合验证。
- `examples/demo.py`：可直接阅读输出的端到端演示。

## 与真实标准的刻意差异

- 没有实现 FIPS 205 的精确 ADRS 编码、上下文/前缀接口和参数集。
- `thash` 是本项目自定义的长度前缀域分离 SHA-256，不是 SLH-DSA-SHA2 的精确函数族。
- 只有一层 XMSS，不是真实的多层 hypertree。
- `n=4`、树高 2，安全强度近乎为零。
- 没有 KAT、侧信道、防故障、常数时间或形式化安全保证。
- nonce 使用可复现的确定性生成器以便测试；生产 RTL 必须使用合适的唯一性/熵方案。

下一步不是继续扩大这个玩具参数，而是建立一份与 FIPS 205 完全一致的软件 golden model，并用官方 KAT/参考实现逐字段比对。详细路线见 `LEARNING_PLAN_CN.md` 和 `OFF_SWITCH_ASSESSMENT_CN.md`。

## 主要资料

- FIPS 205（SLH-DSA，基于 SPHINCS+）：https://csrc.nist.gov/pubs/fips/205/final
- SPHINCS+ v3.1 specification（本地提供的 PDF）
- SPHINCS+ reference code：https://github.com/sphincs/sphincsplus
- RFC 8554（HSS/LMS）：https://datatracker.ietf.org/doc/html/rfc8554
- Off-Switch：https://github.com/JamesPetrie/off-switch
