# PQC、SPHINCS+/SLH-DSA 与 Off-Switch 冲刺学习计划

目标不是“看完密码学材料”，而是在 20 个工作日内达到三个可检验结果：

1. 能从哈希安全性质解释 LM-OTS/WOTS+、Merkle、FORS、XMSS/HT 和 SLH-DSA 的验证链。
2. 能逐字段追踪一份 FIPS 205 签名，并用官方 reference/KAT 验证软件 golden model。
3. 能写出 Off-Switch 的流式 SLH-DSA verifier 微架构、测试计划和首个 RTL 模块。

每天建议 3-5 小时：约 40% 阅读、50% 编码/实验、10% 口头复述与笔记。若只有半天，按顺序推进，不要跳过每日验收。

## 学习方法

每个概念都做同一个四步闭环：

1. 用一句话说明它解决什么问题。
2. 手算一个 2-4 层的小例子。
3. 在本 Python toy 中定位对应函数并打印中间值。
4. 在真实规范中找到精确输入编码、域分离和参数。

遇到公式先问三件事：输入是什么字节序？输出多少字节？哪个地址/域标签防止跨用途复用？这三问直接决定 RTL 是否能和标准互操作。

## 第 0 天：环境基线（已完成）

任务：

- 确认 WSL checkout 与 GitHub main 相同。
- 跑 ECDSA/HSS-LMS lint 和顶层仿真。
- 记录工具链、运行时间和工作树状态。

验收：`top_ecdsa` 16/16、`top_hss` 17/17，通过；见 `OFF_SWITCH_ASSESSMENT_CN.md`。

## 第 1-5 天：哈希签名基础与 RFC 8554

### 第 1 天：哈希函数是怎样成为“公钥密码”的

阅读：SPHINCS+ v3.1 §1、§2.7；复习 preimage、second-preimage、collision、多目标攻击和 Grover 搜索。

编码：运行 `utils.thash`，去掉 domain label 做一次碰撞用途混淆实验；比较有/无长度前缀的拼接歧义。

必须能回答：

- 为什么签名安全不只需要 collision resistance？
- 为什么量子搜索使 n-bit preimage 直觉下降到约 n/2-bit？
- 为什么同一个 SHA-256 core 上仍必须做 domain separation？

验收：写一页笔记，列出 Off-Switch verifier 中 `H_msg/F/H/T_len` 的输入和用途。

### 第 2 天：Lamport、Winternitz chain 与 checksum

阅读：RFC 8554 §4；SPHINCS+ §3.1-§3.6。

编码：逐行跟踪 `wots.message_digits`、`wots.chain`、`wots.sign`、`public_key_from_signature`。手算 `w=4` 的 2-3 条链。

必须能回答：checksum 为什么能阻止把所有消息数字单向“变大”来伪造？`w` 增大时签名大小、chain 长度和速度怎样变化？

验收：篡改一个 WOTS element 后，恢复的 WOTS public key 必须改变。

### 第 3 天：Merkle tree 与 authentication path

阅读：RFC 8554 §5.3-§5.4；SPHINCS+ §4.1.3、§4.1.5、§4.1.7。

编码：画 4 叶树，手算 index 2 的 path；在 `merkle.root_from_path` 逐层打印左右顺序。

必须能回答：为什么 path 是 `h × n` 字节？为什么 leaf index 的每一位决定左右顺序？

验收：错误 index、错误 sibling 和错误 leaf 都不能恢复原 root。

### 第 4 天：LM-OTS -> LMS -> HSS，理解“状态”

阅读：RFC 8554 §2、§4、§5、§6，特别关注 `q`、key exhaustion 和 HSS 私钥更新。

代码映射：

- `verilog/rtl/hss_pkg.sv`：`HSS_LEVELS=2`、`TREE_H=5`、`w=8` 和 license layout。
- `verilog/rtl/hss_verify.sv`：Q -> WOTS -> Kc -> Leaf -> Merkle。
- `test/reference_lms.py`：软件参考和测试向量生成。

验收：用自己的话解释“验证器本身不需要持久状态，但 signer 必须可靠持久化 q；回滚/并发复用 q 会破坏安全”。

### 第 5 天：现有 Off-Switch 数据流

阅读：`security_block.sv`、`hss_verify.sv`、`sha256_wrap.sv`、两份顶层 testbench。

产出：画出 valid/ready、nonce 生命周期、2-of-2 signer 顺序、allowance 更新和错误返回路径。

验收：能指出三个具体瓶颈：完整 packed signature bus、34 × 256-bit `pk_store`、SHA 单上下文不可暂停/恢复。

## 第 6-11 天：完整理解 SPHINCS+/SLH-DSA

### 第 6 天：整体拼装

阅读：SPHINCS+ §1、§6。只先掌握数据流，不钻安全证明。

编码：运行 `examples.demo`，跟踪：

```text
H_msg -> FORS pk -> WOTS+ pk from sig -> XMSS root -> top public root
```

验收：不看资料画出签名布局 `R || SIG_FORS || SIG_HT`，并说明 verifier 为什么只需小公钥。

### 第 7 天：ADRS 与 tweakable hash

阅读：SPHINCS+ §2.7.1-§2.7.3、§7.2.2；随后对照 FIPS 205 的 ADRS 和 SHA2 instantiation。

任务：为 WOTS hash、WOTS pk、tree、FORS tree、FORS roots 列出地址字段；明确哪些字段每次调用必须清零或更新。

验收：做一个“错误地址复用”负例，解释它为何可能造成跨节点/跨用途输入相同。

### 第 8 天：FORS

阅读：SPHINCS+ §5 全部，重点 §5.5-§5.6。

编码：打印 toy digest 的 3 个两位索引、选中秘密值、各自 auth path 和 3 个 roots。

必须能回答：FORS 为什么不是一棵大树？为什么签名泄露的是每棵树一个 secret，而不是整棵树？`k` 与 `a=log(t)` 怎样影响大小和安全？

验收：从 signature 恢复的 FORS pk 与 signer 侧一致。

### 第 9 天：XMSS 与 hypertree

阅读：SPHINCS+ §4.1、§4.2。

任务：从单层 toy 推广到 `d` 层：底层 XMSS 签 FORS pk，上层 XMSS 逐层签下层 root。

验收：给定 `(h,d)`，能计算每层树高 `h/d`、HT 中 WOTS signatures 数量和 auth path 总节点数。

### 第 10 天：SPX keygen/sign/verify

阅读：SPHINCS+ §6.2-§6.5，逐行走伪代码。

任务：做一张三列 trace：规范变量、Python toy 变量、未来 RTL register/FIFO。重点包括 `R`、`md`、`idx_tree`、`idx_leaf`。

验收：对一条 toy signature，从 message 开始手工列出 verifier 每一步的输入输出。

### 第 11 天：参数、安全与工程权衡

阅读：SPHINCS+ §7.1、§8、§9.4、§10、§11。

比较 128s/128f：签名大小、签名时间、验证 hashes、树层数。对 Off-Switch 的 verifier 端，优先 `SLH-DSA-SHA2-128s`。

验收：写出选择说明：为什么不先做 256-bit、为什么选 SHA2、为什么选 small 而不是 fast。

## 第 12-14 天：从教学 toy 过渡到标准 golden model

### 第 12 天：FIPS 205 差异清单

阅读 FIPS 205，建立与 2022 v3.1 的术语/编码差异表。把最终工程名称改为 SLH-DSA；保留“SPHINCS+”用于解释来源。

验收：列出 toy 不合规之处：参数、ADRS、hash instantiation、context/prefix、树层数、KAT 和随机化规则。

### 第 13 天：官方 reference 与 KAT

使用 `https://github.com/sphincs/sphincsplus` 或 FIPS 205 对应参考实现，固定 `SLH-DSA-SHA2-128s`。

任务：

- 构建 reference implementation。
- 生成固定 seed/message/optrand 的 key/signature。
- 保存 PK、signature 和每个字段的 offsets。
- 验证错误消息和每个区域单比特翻转都失败。

验收：标准实现输出长度 7,856 字节；KAT/verify 通过。

### 第 14 天：精确 verifier golden model

不要继续扩展 toy；新建 `golden/slh_dsa_sha2_128s`，严格实现或包装标准代码，并暴露逐阶段 trace。

验收：Python/C golden trace 与 reference 的最终 root、FORS pk、每层 XMSS root 完全一致。

## 第 15-20 天：RTL 微架构与接入

### 第 15 天：冻结流接口和错误模型

定义 32-bit 或 64-bit signature stream、metadata handshake、backpressure、精确长度、reset/abort 和 error code。写 SystemVerilog interface/assertions，暂不接密码逻辑。

验收：随机 stall、截断、超长、重复 last、复位中断都 fail closed。

### 第 16 天：SHA2 function family

实现/验证：BlockPad(PK.seed)、compressed ADRS、F、H、T_len、H_msg/MGF1。先使用一个 context 和 endpoint buffer。

验收：每个函数与 golden model 至少 100 个随机向量逐字节一致。

### 第 17 天：WOTS+ 与 XMSS root-from-signature

复用现有 WOTS/Merkle FSM 思路，但改成 FIPS 205 参数和 16-byte 元素。不要先优化 state loading。

验收：单独模块能从标准 WOTS signature 恢复 leaf，并从 auth path 恢复 XMSS root。

### 第 18 天：FORS pk-from-signature

实现 14 棵、每棵高 12 的 root 恢复；输入完全流式，最多保存当前 secret/node/path 和 14 个 roots。

验收：FORS pk 与 golden trace 一致；任一 secret/path bit 翻转失败。

### 第 19 天：Hypertree 和顶层验证

把 FORS pk 送入 7 层 XMSS（128s 参数），每层消费 WOTS signature + auth path，最后比较 `PK.root`。

验收：官方完整 signature 通过；错误 message/R/FORS/任一 HT 层均失败。

### 第 20 天：Off-Switch 集成、聚合与综合

接入 `security_block` 的 crypto abstraction；保持 ECDSA/HSS 回归。添加 Chip-ID/nonce message encoding 和聚合 root verifier。

验收：

- 旧 ECDSA 16/16、旧 HSS 17/17 仍通过。
- SLH-DSA direct 和 aggregate 顶层测试通过。
- 产出 Yosys/STA：GE、BRAM、Fmax、总 cycles、每阶段 block count。
- 写明签名传输时间。例如 7,856 字节在 32-bit、100 MHz、无 stall 时的纯输入下限约 19.64 微秒；真实延迟由哈希验证主导。

## 之后的优化顺序

1. SHA state export/import，消除 560-byte WOTS endpoint buffer。
2. 将 FORS roots 与 `T_k` 流式压缩。
3. 评估 32/64/256-bit 输入宽度与 scan/UART/management fabric 的匹配。
4. 用 formal assertions 证明：只有完整成功验证才能拉高 allowance increment。
5. 加入 fault detection：FSM/counter duplication、最终 root 双算或时序冗余、错误锁存。
6. 再考虑 crypto diversification 与更高安全类别。

## 每周复盘问题

- 我能否只看一段 signature bytes 就说出它属于 R、FORS 还是哪一层 XMSS？
- 我能否精确写出当前 hash call 的字节串，而不是只说“hash 一下”？
- 我能否指出 verifier 当前需要保存的最小状态？
- 任意 malformed stream 是否都 fail closed？
- Python golden、reference 和 RTL 是否用同一份测试向量？
- 我是否把“教学 toy 通过”误说成“标准实现安全”？

## 阅读顺序（不要从安全证明开始）

1. 本项目 `README.md` + `examples/demo.py`。
2. RFC 8554 §2、§4、§5、§6。
3. SPHINCS+ v3.1 §1、§2.7、§3、§4、§5、§6。
4. SPHINCS+ §7.1、§7.2.2、§8、§9.4、§10、§11。
5. FIPS 205 全文，作为最终互操作规范。
6. SPHINCS+ reference `ref/`：从 `sign.c`/verify call graph 进入，再看 address/hash/thash。
7. Off-Switch `hss_pkg.sv`、`hss_verify.sv`、`sha256_wrap.sv`、`security_block.sv` 和 testbenches。

最终判断标准：当你能把一份 FIPS 205 signature 的字节流逐段送进手画的 RTL FSM，并准确预测每一次 SHA block、保存状态和最终 root 时，就已经从“懂原理”进入“能实现”。
