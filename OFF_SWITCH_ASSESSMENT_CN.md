# Off-Switch 本地环境与 SPHINCS+ 接入评估

检查日期：2026-07-14（Europe/London）

## 结论

本机 WSL 中的 Off-Switch 可以从源码重编译并跑通。WSL checkout 与 GitHub `main` 完全一致，提交为：

```text
eccb54d823b71086a11d069bf321517fe1e29357
```

唯一的环境细节是 Verilator 5.044 安装在 `/home/chenhao/verilator/bin`，非交互 login shell 没有自动加入该路径。因此自动化命令必须显式设置 PATH；编译器本体和代码没有故障。

## 已验证环境

- WSL：Ubuntu 22.04，WSL2。
- 仓库：`/home/chenhao/off-switch`。
- 上游：`https://github.com/JamesPetrie/off-switch`。
- 本地 `HEAD` 与远程 `refs/heads/main`：均为 `eccb54d...`。
- Git submodule `sha256`：`837c5cc396f001d18f2c765721c585716eb439ae`。
- Verilator：5.044（与仓库 CI 目标版本一致）。
- GNU Make：4.3。
- g++：11.4.0。
- Python：3.10.12。
- tracked files 无本地 diff；仓库原有 `.vscode/`、`verilog/build/`、`verilog/build2/` 和 `verilog/dump.fst` 等未跟踪文件。仿真重新生成了 `verilog/build/`，没有修改受版本控制的源码。

## 可复现命令和结果

```bash
export PATH=/home/chenhao/verilator/bin:$PATH
cd /home/chenhao/off-switch/verilog

make lint TOOL=verilator CRYPTO_TYPE=0
make lint TOOL=verilator CRYPTO_TYPE=1
make sim TB=top_ecdsa
make sim TB=top_hss
```

结果：

- ECDSA lint：通过。
- HSS-LMS lint：通过。
- `top_ecdsa`：16/16 tests passed，完整重编译和仿真约 242.5 秒。
- `top_hss`：17/17 tests passed，完整重编译和仿真约 63.4 秒。
- 覆盖了初始 fail-secure、workload gating、2-of-2 多签名、allowance、错误签名、错误 nonce 和 replay rejection。

在 Windows 直接调用时可用：

```powershell
wsl -d Ubuntu2204 -- env `
  PATH=/home/chenhao/verilator/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin `
  make -C /home/chenhao/off-switch/verilog sim TB=top_hss
```

## 当前实现已经具备的能力

1. `security_block.sv` 统一管理 TRNG、nonce、allowance、工作负载门控和验证器选择。
2. `CRYPTO_TYPE=0/1` 在 ECDSA 与 HSS-LMS 间编译期切换。
3. `NUM_SIGNERS=2` 已按固定顺序实现 2-of-2：同一个 nonce 必须通过两个 signer，之后才增加 allowance 并换 nonce。原型计划中的 Multi-key support 已经实装并由顶层测试覆盖。
4. HSS-LMS 当前参数是 `HSS_LEVELS=2`、每层 `TREE_H=5`、LMOTS `w=8`、每个 signer 一个顶层 public root。
5. HSS 验证自下而上复用一个 SHA-256 core；WOTS、Kc、leaf 和 Merkle path 都由 FSM 顺序调度。

## 与原型计划的逐项对应

### 最高优先级：Stateless PQC

建议把“SPHINCS+”工程目标更新为标准名称 **SLH-DSA（FIPS 205）**，第一版选择 `SLH-DSA-SHA2-128s`：

- 与当前 SHA-256 资产最接近。
- 128-bit 类别足以作为第一版原型。
- 公钥 32 字节、私钥 64 字节、签名 7,856 字节。
- `128s` 比 `128f` 更适合 Off-Switch 验证端：签名显著更小，验证哈希工作也更少；签名速度不是芯片端瓶颈，因为签名发生在 host/authority。

SPHINCS+ v3.1 PDF 仍适合学习构造；互操作和 KAT 应以 FIPS 205 为最终规范。

### 必须同时做：Signature streaming

当前 `hss_pkg::license_t` 和 `security_block` 把完整 license 放在超宽 packed bus 上。SPHINCS+/SLH-DSA 签名是 7,856 字节，不能沿用这种接口。

第一版流接口建议：

```text
sig_valid, sig_ready, sig_data[31:0], sig_last, sig_error
```

另有固定大小元数据握手：algorithm/profile、签名总长度、message/nonce、signer index。解析器必须：

- 只接受精确长度；过短、过长、提前 `last` 都 fail closed。
- 按 `R -> FORS -> HT(layer 0..d-1)` 顺序消费。
- 对尚未需要但已经到达的数据施加 backpressure，不构造数万位 MUX。
- 所有 counter 做上界检查，复位/错误后清除中间状态。

### SHA state loading / 多上下文

`sha256_wrap.sv` 只追踪一个连续消息的 `first_q`，不能在一个长 `T_len`/Kc 哈希中途暂停，再用同一 SHA core 跑 WOTS chain 的单块哈希，然后恢复长消息。

三种实现顺序：

1. **功能基线**：保留 WOTS endpoints（SLH-DSA-128s 为 35 × 16 = 560 字节），全部生成后再做 `T_len`。最易验证。
2. **小面积优化**：为 SHA core 增加 state export/import，保存 8 × 32-bit chaining state、block count 和 partial block；在 WOTS chain context 与 `T_len` context 间切换。
3. **吞吐方案**：两个 SHA context/core，一个跑链、一个流式吸收 endpoints。面积更大，最后再评估。

FORS 的 14 个根仅 224 字节，可先存储；确认功能后再做同样的流式压缩。

### Chip ID binding 与 License aggregation

建议签名消息使用版本化、无歧义编码，至少绑定：

```text
protocol_version || algorithm_id || fleet_id || leaf_count || allowance || license_root
```

芯片验证路径：

1. 用本地 nonce 和 nonce auth path 恢复 `nonce_root`。
2. 用烧录 `chip_id`、位置和 `nonce_root` 生成 license leaf。
3. 用 license auth path 恢复 `license_root`。
4. 验证 SLH-DSA 根签名。
5. 成功后才更新 allowance、轮换 nonce。

本目录的 Python aggregation toy 额外签入 `id_root` 并验证 ID path，便于显式观察 ID binding；实际 RTL 可以在威胁模型明确后决定是否保留独立 ID path。

### 暂缓项

- Bitwise gating：不应把“部分签名位匹配”当作安全强度。随机伪造天然约有一半位相等，且算法不可伪造性不分解到每个输出位。只可作为演示性故障扩散，不可作为授权边界。
- Crypto diversification：保留现有 `CRYPTO_TYPE` 架构，但应在 SLH-DSA 基线、流接口和验证覆盖稳定后再扩展。
- ECDSA 窄数据通路/去分支：与当前 stateless PQC 主线正交，单独排期。

## 建议的 RTL 模块边界

```text
security_block
  -> license_stream_parser
  -> slh_dsa_verify_ctrl
       -> h_msg_sha2_mgf1
       -> fors_pk_from_sig
       -> hypertree_verify
            -> wots_pk_from_sig
            -> xmss_root_from_sig
       -> thash_sha2
            -> sha256_context_scheduler
                 -> secworks sha256_core
```

验证端不需要实现 secret PRF 或签名生成。host/authority 用标准库签名；RTL 只实现 public verification，这会显著缩小范围。

## 完成定义

在宣布“SPHINCS+/SLH-DSA 已接入”前，至少满足：

1. 软件 golden model 与 FIPS 205/reference KAT 逐字节一致。
2. RTL 每个构件都有官方向量与随机 differential tests。
3. 顶层覆盖正确签名、每个字段单比特篡改、错误 nonce、错误 chip ID、错误 signer、截断/超长流、重放和复位中断。
4. 仿真无 assertion failure；两种原有 `CRYPTO_TYPE` 回归仍通过。
5. 综合报告包含 GE/BRAM、最大频率、总 cycles、签名输入时间和每个阶段的 hash-block 数。
6. fail closed：任何解析、长度、counter 或 SHA 调度错误都不能增加 allowance。

## 资料版本提醒

- 本地 `sphincs+-r3.1-specification.pdf` 是 2022 年提交规范。
- NIST 已于 2024-08-13 发布 FIPS 205，标准名称为 SLH-DSA，基于 SPHINCS+。
- RFC 8554 明确要求签名 API 更新动态私钥状态，并禁止复用一次性密钥；这正是 stateless 方向要消除的运维风险。
