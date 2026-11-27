# KNX IP Secure 隧道网关安全会话层（Kotlin/JVM）

高端写字楼宇自控系统的 KNXnet/IP Secure 隧道网关会话层参考实现，含模拟设备与攻击模拟测试。

## 运行

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@21   # 任意 JDK 21+
gradle test   # 15 个安全/正常场景测试
gradle run    # 端到端演示（虚拟时钟，确定性输出）
```

## 协议流程

```
设备                          网关
  | --- SESSION_REQUEST (X25519 客户端公钥) --> |   ① 密钥交换：网关不分配任何状态，
  | <-- SESSION_RESPONSE (服务器公钥 + cookie) -- |      只回无状态 cookie（防耗尽）
  | -- SESSION_AUTHENTICATE (cookie 回显 +       |   ② 口令校验：HMAC(PBKDF2(口令),
  |     HMAC(双方公钥) + 心跳间隔) -------------> |      客户端公钥‖服务器公钥)，通过才建会话
  | <--------- SESSION_STATUS (会话 ID) -------- |
  | ============ SECURE_WRAPPER 数据帧 ========== |   ③ 48 位序号 + AES-128-CCM(16B 标签)
  | --- TIMER_NOTIFY (组播, 主干密钥 CCM) ------> |   ④ 路由模式时间同步
```

- 会话密钥：`HMAC(X25519 共享秘密, "session-enc"/"session-salt")` 派生
- 口令密钥：`PBKDF2-HMAC-SHA256(口令, "password-hash.1.secure.ip.knx.org", 65536)`
- 单播 nonce：`salt(5)‖sessionId(2)‖seq48(6)`；组播 nonce：`salt(5)‖senderId(2)‖timerSeq48(6)`

## 威胁模型 → 防御映射

### 1. 伪造时间通知把网段计数往前推（过期 DoS）/ 往回推（重放复活）

`TimingSynchronizer` 三层防御：

1. **标签验证**：TIMER_NOTIFY 携带主干密钥的 CCM 标签，无密钥伪造直接丢弃；
2. **墙钟速率钳制**（纵深防御，应对密钥泄露/内部人）：本地时间估计只能按
   `墙钟间隔 × (1+漂移容差) + 抖动余量` 前进。攻击者即使造出合法标签，
   单次最多把估计值推快几秒 —— 合法报文永远不会被整体"推过期"；
   回推超过抖动余量同样拒绝，防止旧帧在重放窗口里复活；
3. **滑动重放窗口兜底**：组播按发送方维护窗口，窗口内乱序/迟到帧照常接受。

合法场景不误伤：时间广播间隔拉长（夜间节能）时，允许的前进量随墙钟间隔线性放大。

### 2. 会话耗尽攻击占满隧道通道

`SessionServer`：

- **无状态 cookie**（类 DTLS HelloVerifyRequest）：SESSION_REQUEST 阶段零状态分配，
  cookie 用 AES-CCM 加密服务器临时私钥并绑定源地址+客户端公钥。
  伪造源 IP 的泛洪收不到响应、拿不出 cookie，网关上不留任何痕迹；
- **已用 cookie 缓存**（按 30s 时间槽滚动）：录制的合法认证报文重放换不到第二个会话；
- **两级令牌桶**：每源 IP 小桶（突发 4）+ 全局大桶（容量按整楼设备数配置，默认 128）；
- **会话表硬上限**：满时回 BUSY；**已建立会话永不因新连接压力被驱逐**；
- 会话与源地址绑定，防会话劫持。

### 3. 合法场景保障

- **大量面板同时上电**：全局桶容量 ≥ 楼内设备数，100 设备并发建链测试全过；
  组播序号取自同步时间计数，设备先同步再发送；
- **夜间节能心跳拉长**：会话超时 = 申报心跳 × 2.5（钳制 [30s, 900s]），
  心跳 60s 时超时自动放宽到 150s；单播序号与时间无关，心跳再慢也不过期；
  组播窗口按最大心跳 × 2 配置（默认 130s）。

## 代码结构

| 文件 | 职责 |
|---|---|
| `Crypto.kt` | X25519 / PBKDF2 / AES-CCM / HMAC 原语 |
| `Protocol.kt` | 帧编解码、会话报文、单播/组播安全封装、时间通知 |
| `SessionServer.kt` | 网关会话层：无状态 cookie、限流、会话表、序号防重放 |
| `TimingSynchronizer.kt` | 时间计数同步：标签验证 + 墙钟速率钳制 |
| `ReplayWindow.kt` | 组播滑动重放窗口 |
| `Gateway.kt` | 网关整体：单播会话 + 组播路由接收 |
| `SimDevice.kt` | 模拟面板设备 + 受信时间主节点 |
| `Attacker.kt` | 攻击模拟：伪造时间通知、会话泛洪、重放、伪造组播帧 |
| `LoopbackBus.kt` | 进程内同步总线（可注入丢包规则；真实部署换 DatagramChannel 即可） |
| `SecureSessionTest.kt` | 15 个测试：正常路径 + 全部攻击场景 + 合法突发场景 |

## 生产化待办

- `LoopbackBus` 替换为 UDP（`DatagramChannel`），组播加入 224.0.23.12:3671；
- cookie 密钥、主干密钥接入密钥管理（HSM/KMS），支持轮换；
- `TimingSynchronizer.violations`、各 `stats` 计数器接入楼宇监控告警；
- PBKDF2 迭代数恢复 65536（测试/演示中为加速调低）。
