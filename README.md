# jumpbyte-bot 技术解析：消息收发 / WebSocket / 算法 完全整理

> 源码版本：`main @ b252442`（2026-09-03）。语言 Go 100%，单静态二进制。
> 原始仓库：<https://github.com/sisi0318/jumpbyte-bot>（GPL-3.0）
>
> ⚠️ 本项目为 IM 协议逆向工程研究用途。本文仅做技术原理梳理，请遵守所在地法律法规与相关平台服务条款，勿用于任何违规场景。

---

## 0. 一句话总览

**收消息走 WebSocket，发消息默认走 HTTP、可切换到安卓 WS**；二者共用同一套裸 protobuf 编解码器（`proto.go`）和同一套内容/会话逻辑，只是"传输外壳"不同。所有请求都要带签名（`sign`/`qs`/`msToken`/`a_bogus`），媒体资源用对称加密（图片 AES-256-GCM、视频 CENC-AES-128-CTR），登录态靠 cookie + 扫码/短信验证码维持。

```
                    ┌──────────── 外网 (Douyin IM) ────────────┐
                    │                                            │
  终端/脚本 ──HTTP──▶│── /api/*  发消息/撤回/上传/会话  (imapi)   │◀── 发 (默认 http)
  终端/脚本 ──WS────▶│── /ws     事件流(message/connect/disconnect)│── 收 (始终 WS)
                    │── /oriws  原始 protobuf 帧(调试)           │
                    │-- /img /video  媒体解密代理                 │
                    │                                            │
                    │   engine.Client (单账号 IM 引擎)            │
                    │   ├─ WsConn  ── WebSocket 连接/收发帧      │
                    │   ├─ proto.go ── 裸 protobuf 编解码         │
                    │   ├─ httpsend.go ── 发: HTTP(imapi)        │
                    │   ├─ wssend.go   ── 发: WS(frontier 安卓)  │
                    │   ├─ imactions.go── 撤回/表情/回复         │
                    │   ├─ upload.go / video.go ── 媒体上传       │
                    │   └─ convlist.go ── 会话列表               │
                    └────────────────────────────────────────────┘
                              ▲
                              │ 算法层: sign(xor5/sha256)、abogus(SM3+RC4+变体base64)
                              │ media: AES-256-GCM / CENC-AES-128-CTR
```

**目录结构**

```
cmd/bot             入口: 命令分发、扫码登录、收发主循环、断线重连
internal/
  sign              passport web 签名 (sign / qs / xor5 / msToken)
  abogus            a_bogus (SM3 + RC4 变体 + base64 变体)
  login             扫码 / 手机号验证码登录、MFA、cookie 探测
  qr                二维码渲染 + 存 PNG
  engine            IM 引擎 ← 收发/WS/protobuf 核心
    proto.go        裸 protobuf 编解码器
    wsconn.go       WebSocket 连接 (收消息)
    client.go       连接 / 收包解析
    httpsend.go     发消息 HTTP 通道 (imapi) + 通道分发
    wssend.go       发消息 WS 通道 (安卓 frontier, 风控绕行)
    convlist.go     会话列表 (群 + 私信)
    imactions.go    撤回 / 表情 / 回复
    upload.go       图片上传 (SigV4 → TOS)
    video.go        视频分片上传
    videoplay.go    视频播放地址 (batch_play_info)
  media             图片 AES-256-GCM 解密 + 视频 CENC 解密 + 本地代理
  webapi            昵称解析 (带缓存)
  store             sqlite 昵称缓存
  gateway           HTTP + WS 网关
  config            cookie.json / bot.json
```

---

## 1. 接收消息：完整流程（WebSocket）

收消息**始终走 WebSocket**，连接到抖音的 frontier IM 长连接 `wss://frontier-aweme-lf-ipainner.amemv.com/ws/v2`，子协议 `pbbp2`。整个链路是：**建连 → 心跳 → 读帧 → protobuf 宽松解码 → 抠 JSON 消息体 → 组装 IncomingMessage → 投递**。

### 1.1 建连（`client.go`）

`Connect()` → `buildAndroidSendWsURL()` 拼出带签名的 WS URL，`makeClient()` 设置 UA / Cookie / `Sec-WebSocket-Protocol: pbbp2` 等头，最终 `wsConnect()` 握手。

```go
const androidSendWsBase = "wss://frontier-aweme-lf-ipainner.amemv.com/ws/v2"

// access_key = md5("9" + akAppKey + deviceID + "f8a69f1719916z")
func (c *Client) computeAccessKey(deviceID string) string {
    sum := md5.Sum([]byte(akFpID + akAppKey + deviceID + akSalt))
    return hex.EncodeToString(sum[:])
}
```

URL 查询参数（逆自真机安卓端）含 `aid=1128`、`version_code=280400`、`device_platform=android`、`access_key`、时间戳 `ts/_rticket`、`ping-interval=30` 等几十项；请求头里还会透传 `session-tlb-tag`、`x-tt-passport-mfa-token` 等从 cookie 解析出的字段。

### 1.2 WebSocket 连接对象（`wsconn.go`）

`WsConn` 封装 gorilla/websocket：`reader()` goroutine 把每帧二进制数据送进 `msgs` 缓冲 channel（容量 256），`Receive(timeout)` 支持超时轮询，`Send()` 写二进制帧，`Ping()` 发控制帧，`Close()` 发 Close 帧。支持 SOCKS5/HTTP 代理（`applyProxy`），并尊重 `HTTP(S)_PROXY` 环境变量方便抓包。

```go
// wsconn.go 核心
func (c *WsConn) reader() {
    for {
        _, data, err := c.ws.ReadMessage()
        if err != nil { c.setClosed(err); return }
        select {
        case c.msgs <- data:      // 入队
        case <-c.done: return
        }
    }
}
func (c *WsConn) Send(data []byte) error { /* 加锁 */ return c.ws.WriteMessage(websocket.BinaryMessage, data) }
```

### 1.3 收发主循环（`client.go` RunSession）

`RunSession` 是收消息的总控：起一个 15s 心跳 ticker（40s 收不到任何帧判定死亡），主循环 `conn.Receive(1s)` 拿到原始 payload → 更新 `lastRecv` → 回调 `OnRaw`（调试原始帧）→ `handleIncoming(raw, onMessage)` 解析并投递。

```go
for {
    raw, err := conn.Receive(time.Second)
    if err != nil { break }
    if raw != nil { lastRecv.Store(time.Now().Unix()) }
    if len(raw) == 0 { continue }
    if c.OnRaw != nil { c.OnRaw(raw) }   // → 网关 /oriws
    c.handleIncoming(raw, onMessage)
}
```

### 1.4 收包解析（`handleIncoming` + `extractChatItems`）

这是"收到字节 → 业务消息"的关键。由于 **imapi 没有公开 .proto**，项目用**宽松 protobuf 解码**（见第 3 节）：先 `decodeTop(payload)` 得到字段树，再 `collectChat` 两遍扫描：

- **pass 1**：从字段中提取上下文——`field=7(varint/数字串)` 为 sender、`0:1:x:y` 形态字符串为 conv_id、`field=14` 以 `MS4` 开头为 sec_uid。
- **pass 2**：遍历所有 string 字段，尝试 `json.Unmarshal`；命中 `text`/`aweType`/`tkey` 的当成消息 JSON，交给 `parseChatJsonItem` 解析出文本/图片/视频/表情。
- **兜底**：若 protobuf 路径没抠出条目，用正则 `0:1:\d+:\d+` + JSON 片段 `{...}` 直接从裸字节再捞一遍（`collectChatFromRawJson`）。

```go
func (c *Client) parseChatJsonItem(obj map[string]any, senderID, selfUid string) (parsedItem, bool) {
    aweType := toInt(obj["aweType"])
    if aweType == 2702 { image = parseImageRes(...) }        // 图片
    if v, ok := obj["video"].(map[string]any); ok { ... }   // 视频(tkey)
    if aweType == 507  { emoji = parseEmoji(obj) }           // 表情
    // 文本优先级: text > parseMessageDisplay(富文本/卡片/提示)
    // 方向判定: sender == selfUid → "sent"，否则 "recv"
}
```

最终组装成 `IncomingMessage{ConvID, IsGroup, SenderID, SenderMs4, Text, AweType, Image, Video, Emoji, Direction}` 回调给上层。其中：

- **会话 ID 规则**：私信 `0:1:{较小uid}:{较大uid}`（`BuildConvID`，按长度→字典序排序，复刻 TS 逻辑）；群聊是纯数字群号 → `IsGroup=true`。
- **short_id 学习**：收包时从路径 `{8,6,500,5,5}` 等抠出 `conv_short_id` 缓存到 `Client.shortIDs`，发送时回填（这是双通道共用的关键）。
- **方向**：`sender == selfUid` 为 `sent`，否则 `recv`。`message_self` 默认不推，需 `emit_self=true`。

### 1.5 上层投递（`cmd/bot/main.go`）

`runCli` 里把 `deliver` 传给 `runEngineLoop`：投递时若 `gw != nil` 调用 `gw.EmitMessage(m)`（非阻塞，每连接有队列），且只打印 `Direction=="recv"` 的消息；另起 `printCh` goroutine 做昵称解析+打印，**绝不阻塞收包线程**。

`runEngineLoop` 实现**断线自动重连 + cookie 失效自愈**：每轮先 `ProbeCookie`，失效则 `relogin`（有 phone 走短信、否则扫码），重连采用**指数退避**（2s→…→60s 上限）。

```go
for {
    if p := login.ProbeCookie(...); p.Expired { relogin(...) ; continue }
    conn, err := eng.Connect()
    if err != nil { sleep(backoff); backoff *= 2; continue }
    backoff = 2*time.Second
    reason := eng.RunSession(conn, deliver, nil)  // 阻塞直到断开
    gw.EmitDisconnect(reason)
}
```

---

## 2. 发送消息：完整流程（HTTP / WS 双通道）

发送由 `dispatchSend` 统一入口，根据 `bot.json` 的 `send_channel` 分流：

```go
func (c *Client) dispatchSend(convID string, shortID uint64, contentJSON string, msgType int) (SendResult, error) {
    if strings.EqualFold(c.SendChannel, "ws") { return c.sendViaWS(...) }  // 安卓 frontier WS
    return c.sendIMAPI(...)                     