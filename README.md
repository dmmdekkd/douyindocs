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
    return c.sendIMAPI(...)                                                // 默认 HTTP imapi
}
```

**为什么有两个通道？** HTTP 通道（`douyin_pc` web_sdk）在**群聊场景常被风控拒**（返回 `status_code 7523`），此时切到 `ws` 用**安卓端身份**绕开。`content / conv_type / msg_type` 两套完全一致，仅传输外壳不同。

会话类型（`field100.f2`）：`1=单聊`、`2=群聊`；消息类型（`field100.f6`）：`文本=7`、`表情=5`、`图片=27`、`视频=30`。`resolveConvSend` 由 convID 形态决定：`纯数字=群聊`（short_id 即群号）、`0:1:=私信`（short_id 走收包缓存）。

### 2.1 默认通道：HTTP（`httpsend.go`，imapi）

端点是 `https://imapi.douyin.com/v1/message/send`，**body 是 `application/x-protobuf`**（与 WS 帧同构、去掉 frontier 外壳），无 .proto，用裸 proto 编码器按 HAR 硬拼。

**通用外壳 `buildEnvelope`（cmd + f8 内层 + 浏览器指纹 KV）**：

```go
body := concat(
    encodeFieldVarint(1, uint64(cmd)),   // cmd=100 发消息 / 702 撤回
    encodeFieldVarint(2, uint64(nextSeq())),
    encodeLenDelimS(3, webSDKVersion),   // "0.1.8"
    ...
    encodeLenDelim(8, encodeLenDelim(innerField, inner)),  // f8 = 内层
    encodeLenDelimS(9, dev),             // device_id(session_did)
    ...                                  // f15 = 浏览器指纹 KV 一堆
)
```

**发消息 body（`buildIMAPIBody`，cmd=100）** 的 `field100`：

| field | 含义 |
|---|---|
| f1 | conv_id (`0:1:x:y` 或群号) |
| f2 | conv_type (1 单聊 / 2 群聊) |
| f3 | conversation_short_id |
| f4 | content (JSON 字符串) |
| f5 | ext KV: `s:client_message_id`、`s:stime`、`s:mentioned_users` |
| f6 | msg_type (7/5/27/30) |
| f8 | client_message_id |

`content` 的几种形态（对应不同动作）：

- **文本** `imapiTextContent{aweType:700, type:0, richTextInfos:[], text}`
- **图片** `imapiImageContent{resource_url:{oid,skey,data_size,md5}, cover_w/h, from_gallery:1, aweType:2702}`
- **表情** `imapiEmojiContent{display_name,..., url:{uri,url_list}, aweType:507}`
- **回复** `imapiReplyContent{refmsg_type:7, content, refmsg_uid, refmsg_sec_uid, nickname, refmsg_content(嵌套 textContent), version:1}`

`postIMAPIRaw` 设置 `Content-Type: application/x-protobuf`、`User-Agent: douyinim/1.1.33`、`Cookie`、`Referer: https://imdesktop.douyin.com` 后 POST；解析回执：`f3==0` 成功，`f6→f100→f1` 取 `server_msg_id`。

### 2.2 绕风控通道：WS（`wssend.go`，安卓 frontier）

`sendViaWS`：建一个新 WS 连接 → 组 cmd100 帧 → `conn.Send(payload)` → `drainSendAck` 读回执（4s 超时）。

**帧是三层嵌套 protobuf**：

```
外层(frontier) : f1=seq f2=ts f3=5 f4=1 f5=KV{cmd100...} f6/f7="pb" f8=inner
内层(cmd100)   : f1=100 f2=seq f3=sdkver f7=build f8=msgWrapper f9=uid f11="android"
                 f15=KV.. f21/f22=biz/access
msgWrapper     : f100 = field100{ f1 conv_id, f2 conv_type, f3 short, f4 content,
                                 f5 ext..., f6 msg_type, [f7 ticket], f8 cmid, f12 ext }
```

`wsAdaptContent`：群聊主要场景把文本 content 从 web shape 换成**安卓 ch1（`douyin_main`）shape**（`wsCh1TextContent{type, instruction_type, item_type_local, text, aweType:700}`）；图片/表情/视频暂复用。

**回执解析 `matchSendAck`**：沿 `8→6→500→5[*]` 找 KV，匹配 `s:client_message_id==本条` → `f3=server_msg_id`；风控看 `s:vcd_shark_decision=="BLOCK"` 或 `im_callback_status_code ∈ {8101,8610,10502}` → `blocked`。

### 2.3 撤回 / 表情 / 回复（`imactions.go`）

三者都复用 `buildEnvelope`，只改 cmd 号与内层：

- **撤回** `Recall`：cmd=`702`，内层 `f702{conv_id, short_id, 3:1, server_msg_id}`，POST `imapiRecallURL`，判 `f3==0`。
- **表情** `SendEmojiResult`：走 `dispatchSend(..., msgTypeEmoji)`，content `aweType=507`。
- **回复** `SendReplyResult`：content 带 `refmsg_*`，`refmsg_content` 嵌套一条 textContent（含被引原文），`refmsg_type=7`，走 `msgTypeText`。

### 2.4 媒体上传

- **图片** `upload.go`：先 `upload_image` 拿到 `ImageAsset{oid,skey,data_size,md5,cover_w,cover_h}`，再随发图 content 发出；上传走 **SigV4 → TOS**。
- **视频** `video.go` + `videoplay.go`：视频**分片上传**；播放用 `tkey` 换 `batch_play_info` 得 CDN 地址（`get_video_url`），流仍是 CENC 密文，需解密（见 4.2）。

---

## 3. Protobuf 编解码器（`proto.go`）

由于服务端无公开 .proto，项目实现**宽松/猜测式**编解码器，`Type ∈ {varint, string, message, bytes}`。

**编码**：标准 varint + tag(`fieldNum<<3 | wireType`)，`encodeFieldVarint` / `encodeLenDelim` / `encodeKvPair`（重复 KV 字段 `f1=key, f2=value`）。这正是收发两侧组帧的基础。

**解码 `decodeProtobuf`**：逐字节读 tag → 按 wireType(0=varint, 2=length-delimited, 1/5=fixed) 解析。对 length-delimited 字段做**启发式判别**：

```go
looksJson   := 以 '{' 或 '[' 开头
looksToken  := "MS4..." / http:// / https:// / 纯数字 / hex token(uuid/md5)
if looksJson || looksToken {
    → 当作 string
} else {
    → 递归当作嵌套 message；递归失败且是合法 UTF-8 → string；否则 → bytes(base64)
}
```

关键细节：`tryUtf8` 拒绝含控制字符或非法 UTF-8 的字节；`looksHexToken` 防止 uuid/md5 被误当嵌套 message（`depth<8` 限制递归）。

**辅助**：`DecodeToTree` 把原始帧转 `{f,t,v}` 树（bytes→base64），供 `/oriws` 调试；`searchPath(fields, [8,6,500,5,3])` 沿字段号路径提取值——这是**从复杂帧里抠 short_id / server_msg_id 的通用手段**。

---

## 4. 算法详解

### 4.1 签名 `sign`（`internal/sign/sign.go`）

电脑版 passport web 签名，`1:1` 转译自 JS 并对真机 HAR 逐字节验证。

```go
// sign = sha256( 排序后前10个query "k=v&..." + "&" + 排序后body "k=v&..." + "&app_key=" + AppKey )
// qs   = xor5( 排序后前10个参数名 join(",") )
// xor5 = 逐 UTF-8 字节 ^ 0x05 → 两位十六进制（即 code_encrypt）
func SignParams(query, body map[string]string) (signHex, qs string) {
    tStr, keys := sortedKV(query, 10)   // 参数名排序，取前 10
    eStr, _   := sortedKV(body, -1)
    h := tStr + "&" + eStr + "&app_key=" + AppKey  // AppKey="3c452fb664e3de0e936108429a0bc697"
    return hex.EncodeToString(sha256.Sum256([]byte(h))[:]), Xor5(strings.Join(keys, ","))
}
```

- **`sortedKV`**：key 字典序排序，`limit=10` 只取前 10 个（query），body 全取；拼成 `k=v&k=v`。
- **`Xor5`/`CodeEncrypt`**：手写 UTF-8 编码（1/2/3 字节，>0xffff 跳过，与 JS 一致），**每个字节 `^ 5`**，结果按 `%02x` 小写十六进制输出。手机号、短信验证码都用它加密。
- **`MsToken`**：`n` 位随机 base64url 串（字母表 `A-Za-z0-9-_`），默认 128 位。

### 4.2 a_bogus（`internal/abogus/`，`NewabComplete_1.0.1.20.js` 1:1 转译）

web 端反爬签名，三步：**自定义 SM3 哈希 → RC4 变体混淆 → 自定义 base64 变体编码**。`[]int` 全程承载"字符码数组"，避免编码走样。

**① 自定义 SM3（`hash.go`）**
完整实现 SM3 压缩函数：`ctRotl` 循环左移、`ktFF`（前 16 轮 `x^y^z`，后 48 轮 `(x&y)|(x&z)|(y&z)`）、`xtGG`、`sm3reg` 寄存器初值 `[1937774191, 1226093241, ...]`，`compress` 做消息扩展 `t[16..67]` + `t[n+68]=t[n]^t[n+4]`，64 轮置换，`write/fill` 处理分块与填充（append `0x80` + 长度）。输出 32 字节。

**② RC4 变体（`abArr256` / `uaArr256` + `garble`）**
- `abArr256`：S 盒初始化为 `255-i`，打乱时用**乘法递推** `prev=(prev*nums[i]+prev+211)%256`（标准 RC4 是 `i+j`），这是"变体"核心。
- `uaArr256(uaSalt)`：打乱系数用 `[0,1,uaSalt]` 三元素循环。
- `garble`：标准 RC4 PRGA 的变体——`n7=(S[i2]+old)&255`，输出 `input[i] ^ S[n7]`。

**③ base64 变体（`encryptionUa` / `generate`）**
- 用**自定义 64 字符表**：`"ckdp1h4ZKsUB80/Mfvw36XIgR25+WQAlEi7NLboqYTOPuzmFjJnryx9HVGDaStCe"`（加密用）和 `"Dkdpgh2ZmsQB80/MfvV36XI1R45-WUAlEixNLwoqYTOPuzKFjJnry79HbGcaStCe"`（最终输出用），**下标映射 `&16515072>>18`、`&258048>>12`、`&4032>>6`、`&63`**，与标准 base64 完全一致只是字符集不同。
- **padding 用 `=`**（2/1 字节剩余情形）。

**④ 输入编排 `getArr29`**
把 `params`/`data`/`userAgent` 的 SM3 摘要 + 时间戳（`dt1`、`dt2=dt1-rand*10`、`(now-1721836800000)/1209600000`）+ UA 混淆串 + 固定常量（`6241`、`6383`）+ `parArr/dataArr` 的特定下标（`parArr[9]`、`dataArr[10]`…）填入 55 字节的 `arr`，再经固定**置换表 `order`** 重排，拼上 `num...`、`lastNumOne`、`lastNum`（异或校验），最后 `getNumList` 每 3 字节插入随机噪声 → RC4 混淆 → base64 变体输出。

```go
func (c *ctx) generate(url, data, userAgent string) string {
    params := url[strings.Index(url,"?")+1:] + "dhzx"   // 后缀盐 "dhzx"
    data   += "dhzx"
    garbled := c.getGarbledString(params, data, userAgent)
    // topHeader(4字节) + abGarbledCharacters → 自定义 base64 → a_bogus
}
```

### 4.3 媒体加解密（`internal/media/`）

**图片 AES-256-GCM（`image.go`）**：下载回来的图片是加密容器 `IV(12) ‖ 密文 ‖ GCM_tag(16)`，`key = skey`（64 hex → 32 字节）。

```go
func DecryptImage(encrypted []byte, skeyHex string) ([]byte, error) {
    key, _ := hex.DecodeString(skeyHex)      // 必须 32 字节
    iv   := encrypted[:12]
    rest := encrypted[12:]                    // 密文+tag(GCM 约定 tag 附末尾, 与 WebCrypto 一致)
    block, _ := aes.NewCipher(key)
    gcm, _  := cipher.NewGCMWithNonceSize(block, 12)
    return gcm.Open(nil, iv, rest, nil)       // AEAD 解密+验签
}
```
附带 `SniffExt` 按魔数识别 `WEBP/JPG/PNG/HEIC`；`FetchAndDecrypt` 一站式下载+解密；`ImageLink` 暴露本地代理链接。

**视频 CENC-AES-128-CTR（`cenc.go`）**：`key = video.skey` 原始字节（16 字节，AES-128），`iv = senc InitializationVector`（8 或 16 字节，补零到 16）。

```go
// 每个 sample: 把所有 protected 子样本拼成一条, 单条 AES-128-CTR 解密, 再按 {clear,protected} 拼回
// counter 在整条 protected 流上连续递增(跨子样本不重置)
ctr := cipher.NewCTR(block, counter)
if len(subs)==0 { ctr.XORKeyStream(out, data) }  // 整段加密
else {
    for _, s := range subs { protected = append(protected, data[pos+s.Clear : pos+s.Clear+s.Protected]...) }
    ctr.XORKeyStream(dec, protected)
    // 交错拼回: clear 原样 + dec 段
}
```
`mp4cenc.go` 处理 MP4 的 `tenc`/`senc` box 解析，抽出每个 sample 的 IV 与 subsample 表，喂给上述核心。`Videoserver`/`Imageserver` 是本地 HTTP 代理，把解密后明文以 `Range` 支持方式吐给播放器。

---

## 5. 登录与会话（`internal/login/`）

登录态 = `cookie.json`，失效由 `ProbeCookie` 探测（`GET /passport/account/info/v2/`，`user_id>0 && error_code==0` 为活），失效自动重登。

**扫码登录 `QRLogin`**：`get_qrcode` 拿 `qrcode_index_url`（权威，直接编码，避免解 PNG 串位）+ token → 终端渲染二维码（半块/盲文点阵，`GOBOT_QR=braille` 切换）→ 每 2s 轮询 `check_qrconnect` → 状态 `scanned`/`confirmed` → 从 cookie jar 取 `sessionid` + `user_id` 返回。期间若触发 MFA（`account_flow==verify`），`doMfa` 走 `send_code` + `validate_code`，**短信验证码用 `sign.CodeEncrypt`(xor5) 加密**。

**手机号验证码登录 `SMSLogin`**：填 `phone` 到 cookie.json，自动发短信、`PromptSmsCode` 收码（同样 xor5 加密换 cookie），之后 cookie 失效也用同 phone 自愈。

**会话列表 `convlist.go`**：`get_conversations` 同时拉**群 + 私信**，返回 `conv_id`、`is_group`、`conv_type(1私/2群)`、`conv_short_id`、头像、群主 `owner_uid`、`last_msg_time`、`members[{uid,sec_uid,role}]`。

---

## 6. HTTP + WS 网关（`internal/gateway/gateway.go` + `API.md`）

网关把 IM 引擎包装成**类 QQ-bot 的本地 HTTP+WS 服务**（默认 `127.0.0.1:9503`，token 在 `bot.json` 首次自动生成）。

### 6.1 端点

| 端点 | 用途 |
|---|---|
| `ws://host:port/ws?access_token=` | 事件流（连上先 `hello`，之后单向下推） |
| `ws://host:port/oriws?access_token=` | 原始 protobuf 帧（base64 + 解码树），调试/逆向 |
| `POST /api/{动作}` | 发消息/撤回/上传/会话，`Authorization: Bearer` |
| `GET /health` | 存活+账号状态，免鉴权 |
| `GET /img?u=&k=` `/video?tkey=&skey=` | 图片/视频解密代理 |

### 6.2 事件协议（WS `/ws`）

- 连上首帧 `hello`；上行只认 `{"type":"ping"}` → 回 `pong`。
- **`message`**：`{type,id,time,account,self_uid,conv_id,is_group,sender_id,sender_sec_uid,text}` + 可选 `image`/`video`/`emoji` 子对象。图片带 `url`(加密原图)+`link`(解密代理)+各档 `links`；视频带 `tkey/skey`+`play_url`(本地解密明文 MP4)+`poster`；表情 `url` 是明文图无需解密。
- **`message_self`**：自己发的消息，`emit_self=true` 才推。
- **`connect`/`disconnect`**：`reason ∈ {online, disconnect, stop, NETWORK, INVALID}`。

每个 WS 连接是 `wsClient{conn, out chan, done}` + 独立 `writeLoop`（30s ping，写超时 10s）；`push` **非阻塞**：队列满先丢最旧再塞、还满就放弃，**绝不阻塞广播方（收包线程）**——这是高并发下的关键设计。

### 6.3 原始帧 `/oriws`

`EmitRaw` 只在**有订阅者时才解码**：`{type:"raw", time, len, b64, fields:[{f,t,v}]}`，`fields` 即 `DecodeToTree` 输出，用于对照抓包分析未支持的消息类型。

### 6.4 API 动作（`handleAPI` → `dispatch`）

`knownAction`：`get_accounts / send_text / send_image / upload_image / send_emoji / send_reply / send_video / recall / get_video_url / get_conversations`（`send_card`/`send_action_card` 未实现）。统一 `POST` + JSON + token；响应 `{code, data|msg}`，`code: 0成功/400参数/401令牌/404动作/405方法/500执行`。

**发送类通用字段**：`conv_id`(事件里的会话ID) 与 `to_uid`(目标uid,自动拼私信) 二选一、`conv_short_id`(可选更稳)、`account`(单账号可省)。返回统一含 `client_msg_id / server_msg_id / prev_msg_id / conv_id / conversation_short_id / self_uid`。

**典型调用**：

```bash
BASE=http://127.0.0.1:9503
TOKEN=$(python -c "import json;print(json.load(open('bot.json'))['token'])")

# 发文本(回复即把事件的 conv_id 传回)
curl -s -X POST $BASE/api/send_text -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"conv_id":"0:1:1234:5678","text":"你好"}'

# 上传图片 → 发图片
IMG=$(curl -s -X POST $BASE/api/upload_image ... -d '{"data":"'$(base64 photo.jpg)'"}' | python -c "...")
curl -s -X POST $BASE/api/send_image ... -d '{"conv_id":"...","image":'$IMG'}'

# 撤回
curl -s -X POST $BASE/api/recall ... -d '{"conv_id":"...","server_msg_id":"7678..."}'

# 视频播放地址(CENC 密流) / 会话列表
curl -s -X POST $BASE/api/get_video_url ... -d '{"tkey":"...","skey":"..."}'
curl -s -X POST $BASE/api/get_conversations ... -d '{"count":50}'
```

> 回声 bot 范例（API.md）：`websocat` 收 `message` → 提取 `conv_id`/`text` → `curl send_text` 回复，即一个最小可用 bot。

---

## 7. 配置（`internal/config/`）

- **`cookie.json`**（账号，`login` 自动写）：`{id,name,cookie,phone,uid,device_id,proxy,channel,enabled}`；仅验证码登录只需 `{phone,enabled}`。
- **`bot.json`**（网关，首次自动生成 token）：`{host,port,token,queue_limit,emit_self,send_channel}`。`send_channel`: `http`(默认,imapi) 或 `ws`(安卓 frontier,绕群聊风控)。

---

## 8. 关键设计总结

| 维度 | 设计 |
|---|---|
| 收消息 | 始终 WS，宽松 protobuf + 内嵌 JSON 双路径解析，正则兜底 |
| 发消息 | HTTP/WS 双通道，protobuf 同源，仅外壳不同；群聊风控切 WS |
| 会话 | 私信 `0:1:小:大`、群聊纯数字；short_id 收包学习、发送回填 |
| 签名 | sign=SHA256(排序KV+app_key)、qs/xor5/msToken、a_bogus(SM3+RC4变体+base64变体) |
| 媒体 | 图片 AES-256-GCM(skey)、视频 CENC-AES-128-CTR(tkey/skey)、本地解密代理 |
| 可靠性 | 心跳+死亡检测、指数退避重连、cookie 失效探测+自动重登、打印不阻塞收包、WS 队列背压丢 oldest |
| 可调试 | `/oriws` 原始帧(base64+字段树)、`--selftest` 自检算法、`--smoke` 收发联机验证 |

---

## 附录 A：核心源码全文清单

以下按模块收录项目**全部核心实现源文件全文**（不含 `_test.go`，测试已省略但结构一致），保证"完整可对照"。每个文件均从仓库原始 commit 检出，未做修改。



## A. 项目根

### `README.md`

```
# jumpbyte-bot

## 功能

- 登录：扫码（含短信二次验证）或手机号+短信验证码；cookie 失效自动重新登录
- 私信 + 群聊：同一套收发，群聊事件带 `is_group`、群号即 `conv_id`
- 收消息：文本、图片（自动解密）、视频（CENC 自动解密，`play_url` 拿来即播）、表情、系统提示
- 发消息：文本、图片、视频、表情、引用回复（私信/群聊通用）
- 会话列表：`get_conversations` 拉群 + 私信（含成员、群头像、最后消息时间）
- 撤回消息
- HTTP 接口发消息 + WebSocket 推事件（见 [API.md](API.md)）
- 原始 protobuf 帧调试通道 `/oriws`

## 构建

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/jumpbyte-bot ./cmd/bot
```

## 命令

```
jumpbyte-bot              探测 cookie（失效自动重新登录）→ 连接 IM → 启动网关
jumpbyte-bot login        登录（有 phone 走验证码，否则扫码），写 cookie.json
jumpbyte-bot --selftest   自检算法
jumpbyte-bot --smoke      给自己发一条测试消息，验证收发联机
```

首次运行无 `cookie.json` 时自动进入扫码登录，终端打印二维码并存一份 `qrcode.png`。
二维码默认半块渲染，设 `GOBOT_QR=braille` 切换为更小的盲文点阵。

**手机号+验证码登录**：在 `cookie.json` 填 `phone`（`cookie` 留空即可），启动后自动发短信、
终端提示输入验证码换取 cookie；之后 cookie 失效也会用同一手机号重新走验证码登录。
手机号与验证码都用 `code_encrypt`（`XOR 5`+hex）加密，签名与扫码登录同源。

## 配置

`cookie.json`（账号，`login` 自动写入）：

```json
{
  "id": "main",
  "name": "主号",
  "cookie": "sessionid=...; ...",
  "phone": "",
  "uid": "1234567890",
  "device_id": "3249781169",
  "proxy": "",
  "channel": 1,
  "enabled": true
}
```

> 只想用验证码登录：`{ "phone": "13800138000", "enabled": true }` 即可，`cookie`/`uid` 会在登录后自动补全。

`bot.json`（网关，首次启动自动生成，`token` 随机）：

```json
{
  "host": "127.0.0.1",
  "port": 9503,
  "token": "<自动生成>",
  "queue_limit": 1000,
  "emit_self": false,
  "send_channel": "http"
}
```

> `send_channel`：`http`（默认，走 imapi）或 `ws`（走安卓 frontier WS）。二者内容/会话逻辑完全一致，
> 只是传输外壳不同。**群聊在 HTTP 通道可能被风控拒（status_code 7523），此时切 `ws` 用安卓端身份绕开。**

## 网关

启动后监听 `bot.json` 里的 `host:port`（默认 `127.0.0.1:9503`）：

| 端点 | 用途 |
| --- | --- |
| `POST /api/{动作}` | 发消息 / 撤回，`Authorization: Bearer <token>` |
| `ws /ws?access_token=<token>` | 事件流（`message` / `connect` / `disconnect`） |
| `ws /oriws?access_token=<token>` | 原始 protobuf 帧（base64 + 解码树），调试 / 逆向新消息类型 |
| `GET /health` | 存活与账号状态，免鉴权 |

动作：`send_text`、`send_image`、`upload_image`、`send_video`、`send_emoji`、`send_reply`、`recall`、`get_video_url`、`get_conversations`、`get_accounts`。字段与示例见 [API.md](API.md)。

跑起来的终端也可直接输入 `@<conv_id> <文本>` 回车发消息。

### `/oriws` 原始帧

连上后每收到一帧下推：

```json
{
  "type": "raw",
  "time": 1787735984,
  "len": 711,
  "b64": "CNiJ2ZMT...",
  "fields": [
    { "f": 1, "t": "varint", "v": "100" },
    { "f": 8, "t": "message", "v": [ { "f": 100, "t": "message", "v": [ ] } ] }
  ]
}
```

`b64` 是原始字节，`fields` 是宽松解码树（字段号 / 类型 / 值），用来对照抓包分析未支持的消息类型。

## 目录

```
cmd/bot            入口：命令分发、扫码登录、收发主循环
internal/
  sign             passport web 签名（sign / qs / xor5 / msToken）
  abogus           a_bogus（SM3 + RC4变体 + base64变体）
  login            扫码 / 手机号验证码登录、MFA、cookie 探测
  qr               二维码渲染 + 存 PNG
  engine           IM 引擎
    proto.go         裸 protobuf 编解码器
    wsconn.go        WebSocket（收消息）
    client.go        连接 / 收包解析
    httpsend.go      发消息 HTTP 通道（imapi）+ 通道分发
    wssend.go        发消息 WS 通道（安卓 frontier，风控绕行）
    convlist.go      会话列表（群 + 私信）
    imactions.go     撤回 / 表情 / 回复
    upload.go        图片上传（SigV4 → TOS）
    video.go         视频分片上传
  media            图片 AES-256-GCM 解密 + 视频 CENC(AES-128-CTR) 解密 + 本地代理
  webapi           昵称解析（带缓存）
  store            sqlite 昵称缓存
  gateway          HTTP + WS 网关
  config           cookie.json / bot.json
```

收消息走 WebSocket；发消息默认走 HTTP、可切安卓 WS，二者 protobuf 同源，共用一套编解码器与内容/会话逻辑。

## 状态

单账号。`send_card` / `send_action_card` / 点赞未实现。
`message_self`（自己发的消息）需在 `bot.json` 里开 `emit_self`。

## ⚡ 超级无敌宇宙雷霆免责声明 ⚡

- 本项目仅供 **学习、研究与技术交流**，用于理解 IM 协议与逆向工程原理，**严禁用于任何商业、违法或滥用场景**。
- 逆向与调试仅应针对 **你自己拥有的账号与设备**，请勿用于窥探、骚扰、爬取或侵犯任何第三方。
- 一经下载 / 编译 / 运行本项目，**即视为你已完全知悉并同意**：由此产生的一切后果——包括但不限于账号封禁、限流、封号、数据丢失、法律纠纷、社死、被雷劈——**统统由你自己承担**，与作者、贡献者、GitHub 及一切相关方无关。
- 本项目与任何平台 / 公司 **没有任何关联**，非官方、未获授权、不代表其立场，所有商标归各自所有者。
- 请自行遵守你所在地的法律法规以及相关平台的服务条款；因违反而产生的任何责任由使用者独自承担。
- 依据 GPLv3，本软件按「原样」提供，**不附带任何明示或暗示的担保**（包括适销性、特定用途适用性、不侵权等）。
- 作者可能随时删库跑路，本声明拥有横跨三次元的最终解释权。**不接受即刻删除，接受请继续。**

## 许可证

[GPL-3.0](LICENSE)

```

### `API.md`

```
# jumpbyte-bot 网关 API

协议版本 **1**。

- **收事件** —— WebSocket `ws://HOST:PORT/ws?access_token=令牌`，连上先一帧 `hello`，之后单向下推事件
- **原始帧** —— WebSocket `ws://HOST:PORT/oriws?access_token=令牌`，下推每一帧原始 protobuf（调试 / 逆向）
- **发消息 / 动作** —— HTTP `POST http://HOST:PORT/api/{动作}`
- **存活探测** —— HTTP `GET http://HOST:PORT/health`（免令牌）
- 默认地址 `127.0.0.1:9503`，令牌在 `bot.json`（首次启动自动生成）

下文示例统一用这两个变量：

```bash
BASE=http://127.0.0.1:9503
TOKEN=$(python -c "import json;print(json.load(open('bot.json'))['token'])")
```

---

## 通用约定

### 鉴权

HTTP 用请求头，WS 用 query（两者也都支持另一种）：

```
Authorization: Bearer <令牌>
?access_token=<令牌>
```

### 响应

```jsonc
{ "code": 0, "data": { … } }            // 成功
{ "code": 400, "msg": "text 不能为空" }  // 失败
```

判断成败看 `code`（鉴权失败例外，HTTP 401）。

| code | 含义 |
| --- | --- |
| `0` | 成功 |
| `400` | 参数不对 |
| `401` | 令牌无效 |
| `404` | 未知动作 / 路径 |
| `405` | 该动作只接受 POST |
| `500` | 执行失败（`msg` 里有原文） |

### 指定目标

发送类动作共用这几个字段：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `conv_id` | 二选一 | 会话 ID，回消息时用事件里的这个值（私信或群聊都用它） |
| `to_uid` | 二选一 | 目标数字 uid，网关自动拼**私信**会话 |
| `conv_short_id` | 否 | 已知就带上（回复 / 撤回更稳） |
| `account` | 否 | 单账号可省略 |

`conv_id` 两种形态：**私信** `0:1:{较小uid}:{较大uid}`（两 uid 按数值排序）；**群聊** 是纯数字群号
（如 `7681236801654178341`，来自群消息事件或 `get_conversations`）。发送类动作对两者一视同仁，
网关按 `conv_id` 形态自动判定单聊/群聊——回群消息直接把事件里的群 `conv_id` 传回即可。

### 发送类动作的返回

```jsonc
{
  "code": 0,
  "data": {
    "client_msg_id": "3f2a…",
    "server_msg_id": "7678690025631237690",
    "prev_msg_id": "",
    "conv_id": "0:1:1234:5678",
    "conversation_short_id": "",
    "self_uid": "1234"
  }
}
```

---

## 动作

### `get_accounts`

无参数。

```bash
curl -s -X POST $BASE/api/get_accounts -H "Authorization: Bearer $TOKEN"
```

```jsonc
{ "code": 0, "data": [
  { "account": "main", "name": "主号", "uid": "1234",
    "state": "online",   // offline / connecting / online / invalid / disabled
    "message": "online", "online_since": 1787735984 }
] }
```

### `send_text`

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `text` | ✅ | 消息内容 |

```bash
curl -s -X POST $BASE/api/send_text -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"conv_id":"0:1:1234:5678","text":"你好"}'

curl -s -X POST $BASE/api/send_text -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"to_uid":"5678","text":"你好"}'
```

### `upload_image`

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `data` | ✅ | 图片 base64，可带 `data:image/png;base64,` 前缀 |

```bash
curl -s -X POST $BASE/api/upload_image -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d "{\"data\":\"$(base64 -w0 ./photo.jpg)\"}"
```

```jsonc
{ "code": 0, "data": {
  "oid": "…", "skey": "…", "md5": "…",
  "data_size": 123456, "cover_width": 800, "cover_height": 600
} }
```

### `send_image`

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `image` | ✅ | `upload_image` 返回的整个 `data` 对象（至少含 `oid`/`skey`） |

```bash
IMG=$(curl -s -X POST $BASE/api/upload_image -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d "{\"data\":\"$(base64 -w0 ./photo.jpg)\"}" \
  | python -c "import sys,json;print(json.dumps(json.load(sys.stdin)['data']))")

curl -s -X POST $BASE/api/send_image -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d "{\"conv_id\":\"0:1:1234:5678\",\"image\":$IMG}"
```

### `send_video`

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `data` | ✅ | 视频 base64 |
| `cover` | ✅ | 封面图 base64 |
| `width` / `height` | 否 | 视频宽高，不传用封面尺寸兜底 |

```bash
curl -s -X POST $BASE/api/send_video -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d "{
    \"conv_id\":\"0:1:1234:5678\",
    \"data\":\"$(base64 -w0 video.mp4)\",
    \"cover\":\"$(base64 -w0 cover.jpg)\",
    \"width\":720, \"height\":1280
  }"
```

### `send_emoji`

| 字段 | 必填 | 默认 | 说明 |
| --- | --- | --- | --- |
| `url`（或 `uri`） | ✅ | | 表情图地址 |
| `display_name` | 否 | 空 | 展示名，如 `[微笑]` |
| `width` / `height` | 否 | `100` | 宽 / 高 |
| `image_type` | 否 | `png` | 图片类型 |
| `package_id` | 否 | `0` | 表情包 ID |

```bash
curl -s -X POST $BASE/api/send_emoji -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "conv_id":"0:1:1234:5678",
    "url":"https://.../emoji.png",
    "display_name":"[微笑]"
  }'
```

### `send_reply`

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `text` | ✅ | 回复正文 |
| `refmsg_uid` | ✅ | 被回复者数字 uid（取事件里的 `sender_id`） |
| `refmsg_sec_uid` | 否 | 被回复者 sec_uid（取事件里的 `sender_sec_uid`） |
| `nickname` | 否 | 被回复者昵称 |
| `refmsg_text` | 否 | 被回复消息的原文 |

```bash
curl -s -X POST $BASE/api/send_reply -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "conv_id":"0:1:1234:5678", "text":"收到",
    "refmsg_uid":"5678", "refmsg_sec_uid":"MS4wLjAB…", "nickname":"张三",
    "refmsg_text":"在吗"
  }'
```

### `recall`

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `conv_id`（或 `to_uid`） | ✅ | 会话 |
| `server_msg_id` | ✅ | 发送返回里的 `server_msg_id` |
| `conv_short_id` | 否 | 已知带上更稳 |

```bash
curl -s -X POST $BASE/api/recall -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "conv_id":"0:1:1234:5678", "server_msg_id":"7678690025631237690"
  }'
```

返回 `{"code":0,"data":{"ok":true,"conv_id":"…"}}`。

### `get_video_url` —— 取视频播放地址

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `tkey` | ✅ | 视频消息里的 `video.tkey` |
| `skey` | ⭕ | 视频消息里的 `video.skey`；给了就一并回本地解密 `play_url` |

```bash
curl -s -X POST $BASE/api/get_video_url -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"tkey":"tos-cn-o-00061/…","skey":"051d…"}'
```

```jsonc
{ "code": 0, "data": {
  "main_url": "https://…douyinvod.com/…", "backup_url": "https://…",
  "expire_time": 1787908673,
  "play_url": "http://127.0.0.1:9503/video?tkey=…&skey=…"   // 拿来即播的明文 MP4（需传 skey）
} }
```

> `main_url`/`backup_url` 指向的视频流仍是 CENC 加密（`cenc-aes-ctr`，key = `video.skey`）。
> `play_url` 是本地解密代理：打开即得明文可播 MP4，无需自己解密。

### `get_conversations` —— 会话列表（群 + 私信）

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `count` | 否 | 拉取条数，默认 20 |

```bash
curl -s -X POST $BASE/api/get_conversations -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"count":50}'
```

```jsonc
{ "code": 0, "data": { "count": 4, "conversations": [
  {
    "conv_id": "7681236801654178341",   // 群号；直接拿去 send_text 就是群发言
    "is_group": true, "conv_type": 2,   // conv_type: 1 私信 / 2 群聊
    "conv_short_id": "7681236801654178341",
    "avatar": "http://p3-aweme-im-img.byteimg.com/…",
    "owner_uid": "3916922778814715",
    "last_msg_time": 1788427512,
    "members": [
      { "uid": "2119508107991872", "sec_uid": "MS4wLjAB…", "role": 0 },
      { "uid": "3916922778814715", "sec_uid": "MS4wLjAB…", "role": 1 }
    ]
  }
] } }
```

### `GET /video` —— 视频解密代理

免令牌（`<video src>` 带不了 header）。用 `tkey` 换 CDN 地址、下载 CENC MP4、用 `skey`
解密（AES-128-CTR 子样本），出明文可播 MP4；支持 Range，播放器可拖动进度。

```
GET /video?tkey=<video.tkey>&skey=<video.skey>
```

事件里的 `video.play_url` 已拼好此链接，直接丢给 `<video>` 或 ffplay 即可。
下载地址由服务端用 `tkey` 换得（非调用方任意 URL），无 SSRF 面。

### `GET /health`

免令牌。

```bash
curl -s $BASE/health
```

```jsonc
{ "code": 0, "data": { "protocol": 1, "bots": 1, "accounts": [ … ] } }
```

---

## 事件（WebSocket）

连上 `ws://HOST:PORT/ws?access_token=令牌`，先收到 `hello`，之后是事件流。
上行只认 `{"type":"ping"}`（回 `{"type":"pong"}`）。

### `hello`

```jsonc
{ "type": "hello", "protocol": 1, "accounts": [ … ] }
```

### `message`

```jsonc
{ "type": "message", "id": "8e3f…", "time": 1787735984,
  "account": "main", "self_uid": "1234",
  "conv_id": "0:1:1234:5678",       // 群聊时是纯数字群号
  "is_group": false,                // true=群聊；回消息把上面的 conv_id 传回即可
  "sender_id": "5678",
  "sender_sec_uid": "MS4wLjAB…",
  "text": "在吗",
  "image": {                        // 仅图片消息才有
    "oid": "tos-cn-o-00061/…",
    "skey": "…", "md5": "…",
    "data_size": 73119, "cover_width": 600, "cover_height": 600,
    "url":  "https://…",                            // 主 url（origin 优先，加密原图）
    "link": "http://127.0.0.1:9503/img?u=…&k=…",    // 主图解密链接，打开即正常图片
    "origin_url_list": ["…"], "large_url_list": ["…"],
    "medium_url_list": ["…"], "thumb_url_list": ["…"],
    "links": {                                       // 各档拿来即用的解密代理链接
      "origin": "http://…/img?u=…&k=…", "large": "…", "medium": "…", "thumb": "…"
    }
  } }
```

拿 `conv_id` 调 `send_text` 就是回复，调 `send_reply` 就是引用回复。

**视频消息**带 `video`（无 `image`）：

```jsonc
"video": {
  "tkey": "tos-cn-o-00061/…",      // 视频 key，换播放地址用（见 get_video_url）
  "skey": "…",                     // 视频流解密 key（CENC AES-128-CTR）
  "md5": "…",
  "width": 720, "height": 1280,
  "check_pics": ["tos-cn-o-0812/…"],
  "play_url": "http://127.0.0.1:9503/video?tkey=…&skey=…",  // 拿来即播的明文 MP4
  "poster": { … }                  // 封面图，结构同 image（带 links 解密链接）
}
```

**表情消息**带 `emoji`（无 `image`/`video`；`text` 为表情名）：

```jsonc
"emoji": {
  "display_name": "续火花",         // 表情名（也作 text 占位）
  "image_type": "png", "width": 100, "height": 100,
  "url": "https://p3-sign.douyinpic.com/obj/im-resource/…",  // 明文图，直接可显示（不用解密）
  "sticker_id": "…"
}
```

私信、群聊、图片 / 视频 / 表情消息走同一套 `message` 事件，只是多带对应子对象；群聊额外 `is_group:true`。

### `connect` / `disconnect`

```jsonc
{ "type": "connect",    "id":"…","time":…,"account": "main", "self_uid": "1234", "reason": "online" }
{ "type": "disconnect", "id":"…","time":…,"account": "main", "self_uid": "1234", "reason": "NETWORK" }
```

`reason`：`online` / `disconnect` / `stop` / `NETWORK`。

---

## 原始帧调试（`/oriws`）

连上 `ws://HOST:PORT/oriws?access_token=令牌`，先收到 `{"type":"hello","channel":"raw"}`，
之后每收到一帧下推其原始 protobuf，用于对照抓包分析尚未支持的消息类型。

```jsonc
{
  "type": "raw",
  "time": 1787735984,
  "len": 711,
  "b64": "CNiJ2ZMT…",
  "fields": [
    { "f": 1, "t": "varint",  "v": "100" },
    { "f": 8, "t": "message", "v": [
      { "f": 100, "t": "message", "v": [
        { "f": 4, "t": "string", "v": "{\"aweType\":700,…}" }
      ] }
    ] }
  ]
}
```

`t` 取值：`varint`（`v` 是十进制字符串）/ `string` / `message`（`v` 是子树）/ `bytes`（`v` 是 base64）。

---

## 回声 bot

```bash
BASE=http://127.0.0.1:9503
TOKEN=$(python -c "import json;print(json.load(open('bot.json'))['token'])")

websocat "ws://127.0.0.1:9503/ws?access_token=$TOKEN" | while read -r line; do
  type=$(echo "$line" | python -c "import sys,json;print(json.load(sys.stdin).get('type',''))")
  [ "$type" = "message" ] || continue
  conv=$(echo "$line" | python -c "import sys,json;print(json.load(sys.stdin)['conv_id'])")
  text=$(echo "$line" | python -c "import sys,json;print(json.load(sys.stdin)['text'])")
  curl -s -X POST $BASE/api/send_text -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" -d "{\"conv_id\":\"$conv\",\"text\":\"你说的是：$text\"}"
done
```

---

`message_self`（自己发的消息）默认不推，在 `bot.json` 开 `emit_self` 后以 `message_self` 事件下推。

未实现：`send_card` / `send_action_card`、点赞。

```

### `go.mod`

```
module gobot

go 1.25.0

require (
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/liyue201/goqr v0.0.0-20200803022322-df443203d4ea
	golang.org/x/net v0.58.0
	modernc.org/sqlite v1.57.0
	rsc.io/qr v0.2.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.47.0 // indirect
	modernc.org/libc v1.74.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

```


## B. 入口 (cmd/bot)

### `cmd/bot/main.go`

```go
// gobot：私信 bot（Go 版，单静态二进制）。
//
//	gobot login      单独扫码登录 → 写 cookie.json
//	gobot --selftest 自检算法（a_bogus/sign/image/sqlite）
//	gobot            默认 cli：探测 cookie(失效自动扫码) → 连接 IM → 打印收到的消息(含图片链接)，可发消息
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gobot/internal/abogus"
	"gobot/internal/config"
	"gobot/internal/engine"
	"gobot/internal/gateway"
	"gobot/internal/login"
	"gobot/internal/media"
	"gobot/internal/qr"
	"gobot/internal/sign"
	"gobot/internal/store"
	"gobot/internal/webapi"
)

func main() {
	args := os.Args[1:]
	if contains(args, "--selftest") {
		os.Exit(runSelfTest())
	}
	if len(args) > 0 && args[0] == "login" {
		runLogin()
		return
	}
	if len(args) > 0 && args[0] == "--smoke" {
		os.Exit(runSmoke())
	}
	runCli()
}

// runSmoke 向自己发一条带 nonce 的消息，若在收包连接上看到它回显，即证明发帧被服务端接收 + 收包解析可用。
func runSmoke() int {
	acc, err := config.LoadAccount()
	if err != nil {
		fmt.Println("[smoke] 无 cookie.json：" + err.Error())
		return 1
	}
	eng := engine.New(acc.Cookie, acc.UID, acc.DeviceID)
	nonce := "SMK" + sign.MsToken(6)
	selfConv := "0:1:" + acc.UID + ":" + acc.UID
	var hits int
	eng.OnRaw = func(b []byte) {
		if strings.Contains(string(b), nonce) {
			hits++
			fmt.Printf("[smoke] ✔ 收到含 nonce 的帧 len=%d\n", len(b))
		}
	}
	conn, err := eng.Connect()
	if err != nil {
		fmt.Println("[smoke] 连接失败：" + err.Error())
		return 1
	}
	fmt.Println("[smoke] 已连接，2s 后向自己发送 nonce=" + nonce)
	go func() {
		time.Sleep(2 * time.Second)
		if err := eng.SendText(selfConv, "gobot smoke "+nonce); err != nil {
			fmt.Println("[smoke] 发送失败：" + err.Error())
		} else {
			fmt.Println("[smoke] 已发送 → " + selfConv)
		}
	}()
	start := time.Now()
	eng.RunSession(conn, func(m engine.IncomingMessage) {
		fmt.Printf("[smoke] onMessage sender=%s text=%s\n", m.SenderID, m.Text)
	}, func() bool { return time.Since(start) > 12*time.Second })
	fmt.Printf("[smoke] 结束：nonce 命中帧数=%d\n", hits)
	if hits > 0 {
		return 0
	}
	return 2
}

func contains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}

func terminalHooks() login.Hooks {
	reader := bufio.NewReader(os.Stdin)
	return login.Hooks{
		OnQrcode: func(content, png, token string) {
			// 首选服务端权威 URL 直接编码；没有才退回解 PNG（goqr 会串位，仅兜底）。
			var q string
			var err error
			if content != "" {
				q, err = qr.RenderTerminal(content)
			} else {
				q, err = qr.PngToTerminalQR(png)
			}
			if err == nil {
				fmt.Println("\n请用 App 扫码登录：")
				fmt.Println(q)
			} else {
				fmt.Println("二维码渲染失败：" + err.Error())
			}
			if path, e := saveQRPng(content, png); e == nil {
				fmt.Println("二维码已存本地: " + path + "（扫图也行）")
			}
		},
		OnScanned: func(name string) { fmt.Println("已扫码：" + name + "，请在手机上点确认") },
		OnStatus:  func(m string) { fmt.Println("· " + m) },
		PromptSmsCode: func(mobile string) string {
			fmt.Print("短信验证码已发往 " + mobile + "，请输入：")
			s, _ := reader.ReadString('\n')
			return strings.TrimSpace(s)
		},
	}
}

// saveQRPng 把二维码存一份本地 PNG（优先用权威 URL 自己编码，否则退回服务端 PNG）。
func saveQRPng(content, pngBase64 string) (string, error) {
	var data []byte
	var err error
	switch {
	case content != "":
		data, err = qr.RenderPNG(content)
	case pngBase64 != "":
		data, err = base64.StdEncoding.DecodeString(pngBase64)
	default:
		return "", errors.New("无二维码内容")
	}
	if err != nil {
		return "", err
	}
	path := filepath.Join(config.Dir, "qrcode.png")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	if abs, e := filepath.Abs(path); e == nil {
		return abs, nil
	}
	return path, nil
}

// loginAndSave phone 非空走短信验证码登录，否则扫码登录；结果落盘（保留 phone 供下次自愈）。
func loginAndSave(deviceID, phone string) (*config.Account, error) {
	var r *login.LoginResult
	var err error
	if phone != "" {
		r, err = login.SMSLogin(phone, terminalHooks(), deviceID)
	} else {
		r, err = login.QRLogin(terminalHooks(), deviceID)
	}
	if err != nil {
		return nil, err
	}
	name := r.Name
	if name == "" {
		name = "账号" + r.UID
	}
	acc := &config.Account{ID: "main", Name: name, Cookie: r.Cookie, Phone: phone, UID: r.UID, DeviceID: r.DeviceID, Channel: 1, Enabled: true}
	if err := config.SaveAccount(acc); err != nil {
		return nil, err
	}
	return acc, nil
}

func runLogin() {
	did, phone := "", ""
	if a, err := config.LoadAccount(); err == nil {
		did, phone = a.DeviceID, a.Phone
	}
	if phone != "" {
		fmt.Println("=== 短信验证码登录（单账号，手机号 " + phone + "）===")
	} else {
		fmt.Println("=== 扫码登录（单账号）===")
	}
	acc, err := loginAndSave(did, phone)
	if err != nil {
		fmt.Fprintln(os.Stderr, "✘ 登录失败："+err.Error())
		os.Exit(1)
	}
	fmt.Printf("✔ 登录成功：uid=%s 名称=%s\n✔ 已写入 %s\n", acc.UID, acc.Name, config.CookiePath())
}

func runCli() {
	acc, err := config.LoadAccount()
	if err != nil {
		fmt.Println("[bot] 未找到 cookie.json，先扫码登录...")
		acc, err = loginAndSave("", "")
		if err != nil {
			fmt.Fprintln(os.Stderr, "[bot] 启动失败："+err.Error())
			os.Exit(1)
		}
	} else if acc.Cookie == "" && acc.Phone != "" {
		// phone-only 配置：直接短信登录
		fmt.Println("[bot] 检测到 phone，短信验证码登录...")
		if acc, err = loginAndSave(acc.DeviceID, acc.Phone); err != nil {
			fmt.Fprintln(os.Stderr, "[bot] 登录失败："+err.Error())
			os.Exit(1)
		}
	} else {
		p := login.ProbeCookie(acc.Cookie, acc.DeviceID)
		loginWord := "唤起扫码登录"
		if acc.Phone != "" {
			loginWord = "短信验证码登录"
		}
		switch {
		case p.Alive:
			fmt.Printf("[bot] cookie 有效：uid=%s %s\n", p.UID, p.Name)
		case p.Expired:
			fmt.Println("[bot] cookie 已失效（" + p.Reason + "），" + loginWord + "...")
			if acc, err = loginAndSave(acc.DeviceID, acc.Phone); err != nil {
				fmt.Fprintln(os.Stderr, "[bot] 登录失败："+err.Error())
				os.Exit(1)
			}
		default:
			fmt.Println("[bot] cookie 探测异常（" + p.Reason + "），仍尝试启动")
		}
	}
	eng := engine.New(acc.Cookie, acc.UID, acc.DeviceID)

	// 网关：HTTP 发消息 + WS 收事件（像 QQ bot）。token 在 bot.json，首次自动生成。
	var gw *gateway.Gateway
	if bcfg, e := config.LoadBotConfig(); e == nil {
		eng.SendChannel = bcfg.SendChannel // 发送通道：ws / http(默认)
		if strings.EqualFold(bcfg.SendChannel, "ws") {
			fmt.Println("[send] 发送通道：安卓 frontier WS")
		}
		gw = gateway.New(bcfg, acc, eng)
		if e := gw.Start(); e != nil {
			fmt.Println("[gateway] 启动失败：" + e.Error())
			gw = nil
		} else {
			eng.OnRaw = gw.EmitRaw
			fmt.Printf("[gateway] 已启动，令牌见 %s\n", config.BotConfigPath())
			fmt.Printf("[gateway]   收事件  ws://%s/ws?access_token=%s\n", gw.Addr(), bcfg.Token)
			fmt.Printf("[gateway]   原始帧  ws://%s/oriws?access_token=%s\n", gw.Addr(), bcfg.Token)
			fmt.Printf("[gateway]   发消息  POST http://%s/api/send_text  (Authorization: Bearer <令牌>)\n", gw.Addr())
			fmt.Printf("[gateway]   图片    GET  http://%s/img?u=<加密url>&k=<skey>\n", gw.Addr())
			fmt.Printf("[gateway]   存活    GET  http://%s/health\n", gw.Addr())
		}
	}

	fmt.Printf("[cli] 账号 %s (uid=%s) 就绪，连接 IM…\n", acc.Name, acc.UID)
	fmt.Println("[cli] 也可终端直接发：@<conv_id> <文本> 回车；Ctrl-C 退出。")

	// 打印 worker：昵称解析（可能阻塞网络）+ 打印，独立 goroutine，绝不挡收包。
	printCh := make(chan engine.IncomingMessage, 256)
	go func() {
		for m := range printCh {
			onIncoming(acc, m)
		}
	}()
	deliver := func(m engine.IncomingMessage) {
		if gw != nil {
			gw.EmitMessage(m) // 非阻塞（网关内部每连接有队列）
		}
		if m.Direction != "recv" {
			return // 自己发的不打印，避免回声
		}
		select {
		case printCh <- m:
		default: // 打印积压就丢，别挡收包
		}
	}

	// 优雅退出：Ctrl-C / SIGTERM → 关网关（断开 WS）后退出
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n[bot] 收到退出信号，关闭…")
		if gw != nil {
			gw.Stop()
		}
		os.Exit(0)
	}()

	go stdinSender(eng)
	runEngineLoop(eng, acc, gw, deliver)
}

// onIncoming 打印一条收到的消息（图片透出本地代理链接，昵称走缓存解析）。
func onIncoming(acc *config.Account, m engine.IncomingMessage) {
	who := m.SenderID
	if m.SenderMs4 != "" {
		if u, ok := webapi.ResolveUsers(acc.Cookie, []string{m.SenderMs4}, acc.DeviceID)[m.SenderMs4]; ok && u.Nickname != "" {
			who = u.Nickname + "(" + m.SenderID + ")"
		}
	}
	ts := time.Now().Format("15:04:05")
	fmt.Printf("[%s] %s | conv=%s | %s\n", ts, who, m.ConvID, m.Text)
	if m.Image != nil {
		if raw := m.Image.PickURL(); raw != "" {
			fmt.Println("        └─ 图片: " + media.ImageLink(raw, m.Image.Skey))
		}
	}
}

// runEngineLoop 连接 → 收包 → 断线自动重连（带指数退避 + cookie 失效自愈）。
func runEngineLoop(eng *engine.Client, acc *config.Account, gw *gateway.Gateway, deliver func(engine.IncomingMessage)) {
	const maxBackoff = 60 * time.Second
	backoff := 2 * time.Second
	setState := func(s, m string) {
		if gw != nil {
			gw.SetState(s, m)
		}
	}
	emit := func(fn func()) {
		if gw != nil {
			fn()
		}
	}
	for {
		// 每轮先确认 cookie 还有效，失效就重新登录（否则会无限空转重连）
		if p := login.ProbeCookie(acc.Cookie, acc.DeviceID); p.Expired {
			fmt.Println("[engine] cookie 失效，重新登录…")
			setState("invalid", "cookie 失效")
			emit(func() { gw.EmitDisconnect("INVALID") })
			if !relogin(eng, acc) {
				time.Sleep(backoff)
				backoff = capDur(backoff*2, maxBackoff)
				continue
			}
			backoff = 2 * time.Second
		}

		setState("connecting", "connecting")
		conn, err := eng.Connect()
		if err != nil {
			fmt.Printf("[engine] 连接失败：%s，%v 后重试\n", err.Error(), backoff)
			setState("offline", "NETWORK")
			emit(func() { gw.EmitDisconnect("NETWORK") })
			time.Sleep(backoff)
			backoff = capDur(backoff*2, maxBackoff)
			continue
		}
		backoff = 2 * time.Second // 连上就重置退避
		fmt.Println("[engine] 已连接，开始收消息")
		emit(func() { gw.SetOnline(); gw.EmitConnect("online") })

		reason := eng.RunSession(conn, deliver, nil)
		fmt.Printf("[engine] 连接断开(%s)，稍后重连\n", reason)
		setState("offline", reason)
		emit(func() { gw.EmitDisconnect(reason) })
		time.Sleep(2 * time.Second)
	}
}

// relogin cookie 失效时重新登录（有 phone 走短信，否则扫码），原地更新 acc + eng（网关持有 acc 指针，同步生效）。
func relogin(eng *engine.Client, acc *config.Account) bool {
	na, err := loginAndSave(acc.DeviceID, acc.Phone)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[engine] 重新登录失败："+err.Error())
		return false
	}
	*acc = *na
	eng.Cookie, eng.CkUid, eng.DeviceID = na.Cookie, na.UID, na.DeviceID
	return true
}

func capDur(d, max time.Duration) time.Duration {
	if d > max {
		return max
	}
	return d
}

// stdinSender 从标准输入读  @<conv_id> <文本>  并发送。
func stdinSender(eng *engine.Client) {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "@") {
			continue
		}
		rest := strings.TrimSpace(line[1:])
		i := strings.IndexAny(rest, " \t")
		if i <= 0 {
			fmt.Println("[send] 格式：@<conv_id> <文本>")
			continue
		}
		convID := rest[:i]
		text := strings.TrimSpace(rest[i+1:])
		if text == "" {
			continue
		}
		if err := eng.SendText(convID, text); err != nil {
			fmt.Println("[send] 失败：" + err.Error())
		} else {
			fmt.Println("[send] 已发送 → " + convID)
		}
	}
}

func runSelfTest() int {
	ok := true
	check := func(name string, pass bool) {
		mark := "[OK]  "
		if !pass {
			mark = "[FAIL]"
			ok = false
		}
		fmt.Println(" " + mark + " " + name)
	}

	ab := abogus.GetABogus("aid=339757&device_platform=PC", "", "Mozilla/5.0", time.Now().UnixMilli())
	check("a_bogus 生成", len(ab) > 50)

	s, qs := sign.SignParams(map[string]string{"aid": "339757", "device_platform": "PC"}, nil)
	check("sign (sha256)", len(s) == 64)
	check("qs (xor5)", len(qs) > 0)

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	iv := make([]byte, 12)
	_, _ = rand.Read(iv)
	plain := []byte("hello-douyin-image")
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCMWithNonceSize(block, 12)
	ct := gcm.Seal(nil, iv, plain, nil)
	dec, derr := media.DecryptImage(append(append([]byte{}, iv...), ct...), hex.EncodeToString(key))
	check("图片 AES-256-GCM 解密", derr == nil && string(dec) == string(plain))

	store.PutUsers([]store.CachedUser{{SecUID: "__selftest", UID: "1", Nickname: "n"}})
	check("sqlite 昵称缓存", store.GetCachedUsers([]string{"__selftest"})["__selftest"].Nickname == "n")

	if ok {
		fmt.Println("\n自检: 全部通过")
		return 0
	}
	fmt.Println("\n自检: 有失败")
	return 1
}

```


## C. 配置 (internal/config)

### `internal/config/config.go`

```go
// Package config cookie.json 读写（单层扁平对象，强制单账号）。
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Dir cookie.json / bot.db 所在目录，默认当前工作目录（分发时就近放）。
var Dir = "."

// Account 单账号配置。
type Account struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Cookie   string `json:"cookie"`
	Phone    string `json:"phone"` // 填了且 cookie 为空/失效时，改用短信验证码登录
	UID      string `json:"uid"`
	DeviceID string `json:"device_id"`
	Proxy    string `json:"proxy"`
	ProxyAPI string `json:"proxy_api"`
	Channel  int    `json:"channel"`
	Enabled  bool   `json:"enabled"`
}

// CookiePath cookie.json 路径。
func CookiePath() string { return filepath.Join(Dir, "cookie.json") }

// DBPath sqlite 路径。
func DBPath() string { return filepath.Join(Dir, "bot.db") }

func normalize(a *Account) {
	if a.ID == "" {
		a.ID = "main"
	}
	if a.Channel == 0 {
		a.Channel = 1
	}
}

// LoadAccount 读单账号；支持单层对象 / 数组(>1报错) / 纯 cookie 字符串。
func LoadAccount() (*Account, error) {
	data, err := os.ReadFile(CookiePath())
	if err != nil {
		return nil, err
	}
	// 1) 单层对象（cookie 或 phone 至少有一个：phone-only 表示走短信登录）
	var obj Account
	if json.Unmarshal(data, &obj) == nil && (obj.Cookie != "" || obj.Phone != "") {
		obj.Enabled = enabledDefault(data)
		normalize(&obj)
		return &obj, nil
	}
	// 2) 数组
	var arr []Account
	if json.Unmarshal(data, &arr) == nil && len(arr) > 0 {
		if len(arr) > 1 {
			return nil, errors.New("本 bot 仅支持单账号")
		}
		a := arr[0]
		normalize(&a)
		if a.Cookie == "" && a.Phone == "" {
			return nil, errors.New("cookie.json 里既没有 cookie 也没有 phone")
		}
		return &a, nil
	}
	// 3) 纯 cookie 字符串
	var s string
	if json.Unmarshal(data, &s) == nil && s != "" {
		a := Account{Cookie: s, Enabled: true}
		normalize(&a)
		return &a, nil
	}
	return nil, errors.New("cookie.json 应为单层对象、数组或字符串")
}

// enabledDefault：对象里没写 enabled 时默认 true（Go 零值是 false）。
func enabledDefault(data []byte) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) == nil {
		if v, ok := m["enabled"]; ok {
			var b bool
			if json.Unmarshal(v, &b) == nil {
				return b
			}
		}
	}
	return true
}

// SaveAccount 单账号覆盖写（扁平对象）。
func SaveAccount(a *Account) error {
	normalize(a)
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(CookiePath(), append(data, '\n'), 0o644)
}

```

### `internal/config/bot.go`

```go
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

// BotConfig 网关配置（bot.json）。token 首次启动自动生成写回。
type BotConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Token       string `json:"token"`        // 接入令牌，bot 用它连 WS 和调 HTTP
	QueueLimit  int    `json:"queue_limit"`  // 每连接事件积压上限
	EmitSelf    bool   `json:"emit_self"`    // 是否推 message_self（自己发的），单机自测用
	SendChannel string `json:"send_channel"` // 发送通道：ws=安卓 frontier WS；空/http=HTTP imapi(默认)
}

// BotConfigPath bot.json 路径。
func BotConfigPath() string { return filepath.Join(Dir, "bot.json") }

// LoadBotConfig 读 bot.json（缺省值兜底）；没有 token 就生成一个并写回。
func LoadBotConfig() (*BotConfig, error) {
	c := &BotConfig{Host: "127.0.0.1", Port: 9503, QueueLimit: 1000}
	if data, err := os.ReadFile(BotConfigPath()); err == nil {
		_ = json.Unmarshal(data, c) // 覆盖到缺省值上
	}
	if c.Host == "" {
		c.Host = "127.0.0.1"
	}
	if c.Port == 0 {
		c.Port = 9503
	}
	if c.QueueLimit == 0 {
		c.QueueLimit = 1000
	}
	if c.Token == "" {
		c.Token = randToken()
		_ = SaveBotConfig(c)
	}
	return c, nil
}

// SaveBotConfig 覆盖写 bot.json。
func SaveBotConfig(c *BotConfig) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(BotConfigPath(), append(data, '\n'), 0o644)
}

func randToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

```


## D. 签名算法 (internal/sign)

### `internal/sign/sign.go`

```go
// Package sign 电脑版 passport web 签名（1:1 转译自 TS 版，已对真机 HAR 逐字节验证）。
//
//	sign = sha256( 排序后前10个 query "k=v&..." + "&" + 排序后 body "k=v&..." + "&app_key=" + AppKey )
//	qs   = xor5( 排序后前10个参数名 join(",") )
//	xor5 = 逐 UTF-8 字节 ^ 0x05 → 两位十六进制（即 code_encrypt）
package sign

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// AppKey 取自客户端 renderer（appKey:"3c452fb6..."）。
const AppKey = "3c452fb664e3de0e936108429a0bc697"

// Xor5 = code_encrypt：UTF-8 编码后每字节 ^5，两位十六进制。
// 与 JS 的手写 UTF-8(1/2/3 字节，跳过代理对)保持一致。
func Xor5(s string) string {
	var out []byte
	for _, r := range s {
		c := int(r)
		switch {
		case c <= 0x7f:
			out = append(out, byte(c))
		case c <= 0x7ff:
			out = append(out, byte(0xc0|((c>>6)&0x1f)), byte(0x80|(c&0x3f)))
		case c <= 0xffff:
			out = append(out, byte(0xe0|((c>>12)&0x0f)), byte(0x80|((c>>6)&0x3f)), byte(0x80|(c&0x3f)))
			// > 0xffff 跳过，与 JS 一致
		}
	}
	var sb strings.Builder
	sb.Grow(len(out) * 2)
	for _, b := range out {
		const hexd = "0123456789abcdef"
		v := b ^ 5
		sb.WriteByte(hexd[v>>4])
		sb.WriteByte(hexd[v&0xf])
	}
	return sb.String()
}

// CodeEncrypt 别名（短信验证码加密）。
func CodeEncrypt(s string) string { return Xor5(s) }

// sortedKV 排序 key，取前 limit 个（limit<0 表示全部），拼 "k=v&k=v"，返回 (str, keys)。
func sortedKV(m map[string]string, limit int) (string, []string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if limit >= 0 && limit < len(keys) {
		keys = keys[:limit]
	}
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + m[k]
	}
	return strings.Join(parts, "&"), keys
}

// SignParams 计算 sign + qs。query 为完整 query（不含 sign/qs/msToken/a_bogus），body 为 POST 表单（GET 传 nil）。
func SignParams(query, body map[string]string) (signHex, qs string) {
	tStr, keys := sortedKV(query, 10)
	eStr, _ := sortedKV(body, -1)
	h := tStr + "&" + eStr + "&app_key=" + AppKey
	sum := sha256.Sum256([]byte(h))
	return hex.EncodeToString(sum[:]), Xor5(strings.Join(keys, ","))
}

const msAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// MsToken 生成 n 位随机 base64url 串（默认 128）。
func MsToken(n int) string {
	if n <= 0 {
		n = 128
	}
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = msAlphabet[b[i]&63]
	}
	return string(b)
}

```


## E. a_bogus 算法 (internal/abogus)

### `internal/abogus/abogus.go`

```go
package abogus

import (
	"crypto/rand"
	"encoding/binary"
	"strconv"
	"strings"
)

// ctx 承载可注入的时间与随机（便于对拍 JS）。
type ctx struct {
	now  int64          // Date.now() 毫秒
	rand func() float64 // Math.random()
}

// ---- base64 变体 ----

func encryptionUa(ss []int) []int {
	const str = "ckdp1h4ZKsUB80/Mfvw36XIgR25+WQAlEi7NLboqYTOPuzmFjJnryx9HVGDaStCe"
	var out []int
	j := 0
	for i := 0; i < len(ss); i += 3 {
		if i+3 <= len(ss) {
			number := ((ss[i] & 255) << 16) | ((ss[i+1] & 255) << 8) | (ss[i+2] & 255)
			out = append(out, int(str[(number&16515072)>>18]), int(str[(number&258048)>>12]), int(str[(number&4032)>>6]), int(str[number&63]))
		}
		if i+3 > len(ss) {
			switch len(ss) - j {
			case 2:
				b := ss[j+1]<<8 | ss[j]<<16
				out = append(out, int(str[(b&16515072)>>18]), int(str[(b&258048)>>12]), int(str[(b&4032)>>6]), int('='))
			case 1:
				b := ss[j] << 16
				out = append(out, int(str[(b&16515072)>>18]), int(str[(b&258048)>>12]), int('='), int('='))
			}
		}
		j += 3
	}
	return out
}

// ---- RC4 变体 ----

func abArr256() []int {
	nums := make([]int, 256)
	for i := range nums {
		nums[i] = 255 - i
	}
	prev := 0
	const lm = 211
	for i := 0; i < 256; i++ {
		prev = (prev*nums[i] + prev + lm) % 256
		nums[i], nums[prev] = nums[prev], nums[i]
	}
	return nums
}

func uaArr256(uaSalt int) []int {
	nums := make([]int, 256)
	for i := range nums {
		nums[i] = 255 - i
	}
	prev := 0
	lm := []int{0, 1, uaSalt} // String.fromCharCode(0.0039,1,ua_salt) → [0,1,ua_salt]
	for i := 0; i < 256; i++ {
		prev = (prev*nums[i] + prev + lm[i%3]) % 256
		nums[i], nums[prev] = nums[prev], nums[i]
	}
	return nums
}

func garble(arr256, input []int) []int {
	n4 := 0
	ans := make([]int, 0, len(input))
	for i := 0; i < len(input); i++ {
		n2 := (i + 1) % 256
		n4 = (n4 + arr256[n2]) % 256
		old := arr256[n2]
		arr256[n2] = arr256[n4]
		arr256[n4] = old
		n7 := (arr256[n2] + old) % 256
		ans = append(ans, input[i]^arr256[n7])
	}
	return ans
}

func uaGarbledCharacters(ua []int, uaSalt int) []int { return garble(uaArr256(uaSalt), ua) }
func abGarbledCharacters(input []int) []int          { return garble(abArr256(), input) }

// ---- 固定数据 / 派生 ----

func getArr2() []int {
	// JS switch 两分支最终都是这串（第二次赋值覆盖）
	return codesOf("784|943|1707|1019|1707|1019|1707|1067|MacIntel")
}

func getLast3Num(dateTime1 int64) []int {
	s := strconv.Itoa(int((dateTime1+3)&255)) + ","
	return codesOf(s)
}

func b8(v int64, k uint) int { return int((v >> k) & 255) }

func getLastNum2(arr1, arr []int) int {
	idx := []int{}
	// arr1[0..7]
	x := arr1[0] ^ arr1[1] ^ arr1[2] ^ arr1[3] ^ arr1[4] ^ arr1[5] ^ arr1[6] ^ arr1[7]
	for _, i := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 25, 26, 27, 29, 30, 31, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 50, 51, 53, 54} {
		x ^= arr[i]
	}
	_ = idx
	return x
}

func (c *ctx) getNumList(arr0, arrAr []int) []int {
	var numList []int
	for i := 0; i < len(arrAr); i += 3 {
		if i+2 >= len(arrAr) {
			if i+1 >= len(arrAr) {
				numList = append(numList, arrAr[i])
			} else {
				numList = append(numList, arrAr[i], arrAr[i+1])
			}
		} else {
			random := int(c.rand()*1000) & 255
			numList = append(numList,
				(random&145)|(arrAr[i]&110),
				(random&66)|(arrAr[i+1]&189),
				(random&44)|(arrAr[i+2]&211),
				((arrAr[i]&145)|(arrAr[i+1]&66))|(arrAr[i+2]&44))
		}
	}
	out := append([]int(nil), arr0...)
	return append(out, numList...)
}

func (c *ctx) topHeader() []int {
	num1 := int(c.rand()*65535) & 255
	num2 := int(c.rand() * 40)
	return []int{
		(num1 & 170) | (3 & 85), (num1 & 85) | (3 & 170),
		(num2 & 170) | (82 & 85), (num2 & 85) | (82 & 170),
	}
}

func (c *ctx) randomGarbledList() []int {
	r1 := int(c.rand() * 65535)
	num1a := r1 & 255
	num2a := (r1 >> 8) & 255
	num1b := int(c.rand() * 240)
	num2b := (int(c.rand()*255) & 77) | 2 | 16 | 32 | 128
	return []int{
		(num1a & 170) | (1 & 85), (num1a & 85) | (1 & 170), (num2a & 170) | (0 & 85), (num2a & 85) | (0 & 170),
		(num1b & 170) | (1 & 85), (num1b & 85) | (1 & 170), (num2b & 170) | (0 & 85), (num2b & 85) | (0 & 170),
	}
}

func (c *ctx) getArr29(dt1, dt2 int64, params, data, userAgent string) []int {
	parArr := getArr(getArrStr(params))
	dataArr := getArr(getArrStr(data))
	uaSalt := 0
	browserArr := getArr(encryptionUa(uaGarbledCharacters(codesOf(userAgent), uaSalt)))
	num := getArr2()
	dateTime3 := int((c.now - 1721836800000) / 1209600000)
	arr0 := c.randomGarbledList()

	arr := make([]int, 55)
	arr[0] = 41
	arr[1] = dateTime3
	arr[2] = 5
	arr[3] = (int(dt1-dt2) + 3) & 255
	arr[4] = b8(dt1, 0)
	arr[5] = b8(dt1, 8)
	arr[6] = b8(dt1, 16)
	arr[7] = b8(dt1, 24)
	arr[8] = b8(dt1, 32)
	arr[9] = b8(dt1, 40)
	arr[10] = 1
	arr[11] = 0
	arr[12] = 1
	arr[13] = 0
	arr[14] = 1
	arr[15] = 0
	arr[16] = 0
	arr[17] = 0
	arr[18] = uaSalt & 255
	arr[19] = (uaSalt >> 8) & 255
	arr[20] = (uaSalt >> 16) & 255
	arr[21] = (uaSalt >> 24) & 255
	arr[22] = parArr[9]
	arr[23] = parArr[18]
	arr[24] = 3
	arr[25] = parArr[3]
	arr[26] = dataArr[10]
	arr[27] = dataArr[19]
	arr[28] = 4
	arr[29] = dataArr[4]
	arr[30] = browserArr[11]
	arr[31] = browserArr[21]
	arr[32] = 5
	arr[33] = browserArr[5]
	arr[34] = b8(dt2, 0)
	arr[35] = b8(dt2, 8)
	arr[36] = b8(dt2, 16)
	arr[37] = b8(dt2, 24)
	arr[38] = b8(dt2, 32)
	arr[39] = b8(dt2, 40)
	arr[40] = 3
	arr32 := 6241
	arr[41] = (arr32 >> 0) & 255
	arr[42] = (arr32 >> 8) & 255
	arr[43] = (arr32 >> 16) & 255
	arr[44] = (arr32 >> 24) & 255
	arr36 := 6383
	arr[45] = arr36 & 255
	arr[46] = (arr36 >> 8) & 255
	arr[47] = (arr36 >> 16) & 255
	arr[48] = (arr36 >> 24) & 255
	lastNumOne := getLast3Num(dt1)
	arr[49] = len(num)
	arr[50] = len(num) & 255
	arr[51] = (len(num) >> 8) & 255
	arr[52] = len(lastNumOne)
	arr[53] = len(lastNumOne) & 255
	arr[54] = (len(lastNumOne) >> 8) & 255
	lastNum := getLastNum2(arr0, arr)

	order := []int{9, 18, 30, 35, 47, 4, 44, 19, 10, 23, 12, 40, 25, 42, 3, 22, 38, 21, 5, 45, 1, 29, 6, 43, 33, 14, 36, 37, 2, 46, 15, 48, 31, 26, 16, 13, 8, 41, 27, 17, 39, 20, 11, 0, 34, 7, 50, 51, 53, 54}
	arr2 := make([]int, len(order))
	for i, o := range order {
		arr2[i] = arr[o]
	}
	newArr2 := append(append(append([]int(nil), arr2...), num...), lastNumOne...)
	newArr2 = append(newArr2, lastNum)
	return c.getNumList(arr0, newArr2)
}

func (c *ctx) getGarbledString(params, data, userAgent string) []int {
	t1 := c.now
	t2 := t1 - int64(c.rand()*10)
	arr29 := c.getArr29(t1, t2, params, data, userAgent)
	a := c.topHeader()
	b := abGarbledCharacters(arr29)
	return append(a, b...)
}

// generate 用给定 ctx 生成 a_bogus。
func (c *ctx) generate(url, data, userAgent string) string {
	params := url[strings.Index(url, "?")+1:] + "dhzx"
	data += "dhzx"
	garbled := c.getGarbledString(params, data, userAgent)
	const shortStr = "Dkdpgh2ZmsQB80/MfvV36XI1R45-WUAlEixNLwoqYTOPuzKFjJnry79HbGcaStCe"
	var sb strings.Builder
	j := 0
	for i := 0; i <= len(garbled); i += 3 {
		if i+3 <= len(garbled) {
			baseNum := garbled[i+2] | garbled[i+1]<<8 | garbled[i]<<16
			sb.WriteByte(shortStr[(baseNum&16515072)>>18])
			sb.WriteByte(shortStr[(baseNum&258048)>>12])
			sb.WriteByte(shortStr[(baseNum&4032)>>6])
			sb.WriteByte(shortStr[baseNum&63])
		}
		if i+3 > len(garbled) {
			switch len(garbled) - j {
			case 2:
				baseNum := garbled[j+1]<<8 | garbled[j]<<16
				sb.WriteByte(shortStr[(baseNum&16515072)>>18])
				sb.WriteByte(shortStr[(baseNum&258048)>>12])
				sb.WriteByte(shortStr[(baseNum&4032)>>6])
				sb.WriteByte('=')
			case 1:
				baseNum := garbled[j] << 16
				sb.WriteByte(shortStr[(baseNum&16515072)>>18])
				sb.WriteByte(shortStr[(baseNum&258048)>>12])
				sb.WriteByte('=')
				sb.WriteByte('=')
			}
		}
		j += 3
	}
	return sb.String()
}

// cryptoFloat 返回 [0,1) 的加密随机（生产用）。
func cryptoFloat() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53)
}

// GetABogus 生产入口：真实时间 + 加密随机。url=query串(不含前导?可含)，data=POST体，userAgent=UA。
func GetABogus(url, data, userAgent string, nowMs int64) string {
	c := &ctx{now: nowMs, rand: cryptoFloat}
	return c.generate(url, data, userAgent)
}

```

### `internal/abogus/hash.go`

```go
// Package abogus 1:1 转译自 NewabComplete_1.0.1.20.js（web a_bogus）。
// 全程用 []int 承载“字符码数组”（对应 JS 的 String.fromCharCode/charCodeAt），避免编码走样。
package abogus

// ctRotl 循环左移 32 位（JS: (e<<t | e>>>32-t) >>> 0）。
func ctRotl(e uint32, t uint) uint32 {
	t %= 32
	if t == 0 {
		return e
	}
	return (e << t) | (e >> (32 - t))
}

func stConst(e int) uint32 {
	if e >= 0 && e < 16 {
		return 2043430169
	}
	return 2055708042
}

func ktFF(e int, t, r, n uint32) uint32 {
	if e < 16 {
		return t ^ r ^ n
	}
	return (t & r) | (t & n) | (r & n)
}

func xtGG(e int, t, r, n uint32) uint32 {
	if e < 16 {
		return t ^ r ^ n
	}
	return (t & r) | (^t & n)
}

// sm3reg 对应 JS 里的 reg 对象。
type sm3reg struct {
	chunk []int
	reg   [8]uint32
	size  int
}

func newReg() *sm3reg {
	return &sm3reg{
		reg: [8]uint32{1937774191, 1226093241, 388252375, 3666478592, 2842636476, 372324522, 3817729613, 2969243214},
	}
}

func (g *sm3reg) compress(r []int) {
	if len(r) < 64 {
		return
	}
	t := make([]uint32, 132)
	for i := 0; i < 16; i++ {
		t[i] = uint32(r[4*i])<<24 | uint32(r[4*i+1])<<16 | uint32(r[4*i+2])<<8 | uint32(r[4*i+3])
	}
	for n := 16; n < 68; n++ {
		o := t[n-16] ^ t[n-9] ^ ctRotl(t[n-3], 15)
		o = o ^ ctRotl(o, 15) ^ ctRotl(o, 23)
		t[n] = o ^ ctRotl(t[n-13], 7) ^ t[n-6]
	}
	for n := 0; n < 64; n++ {
		t[n+68] = t[n] ^ t[n+4]
	}
	i := g.reg // copy
	for a := 0; a < 64; a++ {
		c := ctRotl(i[0], 12) + i[4] + ctRotl(stConst(a), uint(a))
		c = ctRotl(c, 7)
		f := c ^ ctRotl(i[0], 12)
		u := ktFF(a, i[0], i[1], i[2])
		u = u + i[3] + f + t[a+68]
		s := xtGG(a, i[4], i[5], i[6])
		s = s + i[7] + c + t[a]
		i[3] = i[2]
		i[2] = ctRotl(i[1], 9)
		i[1] = i[0]
		i[0] = u
		i[7] = i[6]
		i[6] = ctRotl(i[5], 19)
		i[5] = i[4]
		i[4] = s ^ ctRotl(s, 9) ^ ctRotl(s, 17)
	}
	for l := 0; l < 8; l++ {
		g.reg[l] = g.reg[l] ^ i[l]
	}
}

func (g *sm3reg) write(o []int) {
	g.size += len(o)
	i := 64 - len(g.chunk)
	if len(o) < i {
		g.chunk = append(g.chunk, o...)
		return
	}
	end := i
	if end > len(o) {
		end = len(o)
	}
	g.chunk = append(g.chunk, o[:end]...)
	for len(g.chunk) >= 64 {
		g.compress(g.chunk[:64])
		if i < len(o) {
			hi := i + 64
			if hi > len(o) {
				hi = len(o)
			}
			g.chunk = append([]int(nil), o[i:hi]...)
		} else {
			g.chunk = nil
		}
		i += 64
	}
}

func (g *sm3reg) fill() {
	o := 8 * g.size
	g.chunk = append(g.chunk, 128)
	i := len(g.chunk) % 64
	if 64-i < 8 {
		i -= 64
	}
	for ; i < 56; i++ {
		g.chunk = append(g.chunk, 0)
	}
	for a := 0; a < 4; a++ {
		c := o / 4294967296
		g.chunk = append(g.chunk, (c>>(8*(3-a)))&255)
	}
	for a := 0; a < 4; a++ {
		g.chunk = append(g.chunk, (o>>(8*(3-a)))&255)
	}
}

// getArr 自定义 SM3：输入字符码数组，返回 32 字节（字符码数组）。
func getArr(input []int) []int {
	g := newReg()
	g.write(input)
	g.fill()
	for i := 0; i+64 <= len(g.chunk); i += 64 {
		g.compress(g.chunk[i : i+64])
	}
	out := make([]int, 32)
	for i := 0; i < 8; i++ {
		c := g.reg[i]
		out[4*i+3] = int(c & 255)
		c >>= 8
		out[4*i+2] = int(c & 255)
		c >>= 8
		out[4*i+1] = int(c & 255)
		c >>= 8
		out[4*i] = int(c & 255)
	}
	return out
}

// codesOf 字符串 → 字符码数组（UTF-8 字节，对应 JS write 的 encodeURIComponent 口径）。
func codesOf(s string) []int {
	b := []byte(s)
	out := make([]int, len(b))
	for i, c := range b {
		out[i] = int(c)
	}
	return out
}

func getArrStr(s string) []int { return getArr(codesOf(s)) }

```


## F. 登录与会话 (internal/login)

### `internal/login/client.go`

```go
package login

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"gobot/internal/abogus"
	"gobot/internal/sign"
)

const aid = "339757"
const defaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) douyinim/1.1.31 Chrome/130.0.6723.58 Electron/33.4.11 Safari/537.36"

func nowMs() int64 { return time.Now().UnixMilli() }

func randHex(n int) string {
	const hexd = "0123456789abcdef"
	b := make([]byte, n)
	// 复用 msToken 的随机源足够；这里简单用时间+计数亦可，但直接 crypto 更稳
	src := []byte(sign.MsToken(n))
	for i := range b {
		b[i] = hexd[src[i]&0xf]
	}
	return string(b)
}

// CookieJar 极简 cookie jar。
type CookieJar struct{ store map[string]string }

func NewJar() *CookieJar { return &CookieJar{store: map[string]string{}} }

func (j *CookieJar) Load(s string) {
	for _, part := range strings.Split(s, ";") {
		kv := strings.TrimSpace(part)
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		j.store[kv[:i]] = kv[i+1:]
	}
}

func (j *CookieJar) Update(res *http.Response) {
	for _, c := range res.Cookies() {
		if c.Value == "" || strings.EqualFold(c.Value, "deleted") {
			delete(j.store, c.Name)
		} else {
			j.store[c.Name] = c.Value
		}
	}
}

func (j *CookieJar) Header() string {
	parts := make([]string, 0, len(j.store))
	for k, v := range j.store {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, "; ")
}

func (j *CookieJar) Get(name string) string { return j.store[name] }

// Client passport web 请求器。
type Client struct {
	UA          string
	DeviceID    string
	fingerprint string
	Jar         *CookieJar
	hc          *http.Client
}

// NewClient deviceID 为空则新生成；cookie 非空则预置。
func NewClient(deviceID, cookie string) *Client {
	if deviceID == "" {
		deviceID = GenDeviceID()
	}
	c := &Client{
		UA:          defaultUA,
		DeviceID:    deviceID,
		fingerprint: buildFingerprint(deviceID),
		Jar:         NewJar(),
		hc:          &http.Client{Timeout: 30 * time.Second},
	}
	if cookie != "" {
		c.Jar.Load(cookie)
	}
	return c
}

func (c *Client) normalBase() map[string]string {
	return map[string]string{
		"passport_jssdk_version": "2.4.12", "passport_jssdk_type": "normal", "is_from_ttaccountsdk": "1",
		"aid": aid, "language": "zh", "ts": fmt.Sprint(time.Now().Unix()),
		"account_sdk_source": "web", "account_sdk_source_info": c.fingerprint,
		"p_js_v": "2.4.12", "p_js_t": "pro", "p_zt": "3.3.5", "p_ver": "1.0.29",
		"request_host": "file://", "p_bd": "1.0.1.7", "biz_trace_id": randHex(8),
		"device_id": c.DeviceID, "iid": "0", "version_code": "1.1.31", "device_platform": "PC",
		"is_from_iesaccountsaas": "1", "is_new_login": "1",
	}
}

func (c *Client) liteBase() map[string]string {
	return map[string]string{
		"passport_jssdk_version": "5.1.2", "passport_jssdk_type": "lite", "is_from_ttaccountsdk": "1",
		"aid": aid, "language": "zh", "account_app_language": "zh", "new_authn_sdk_version": "1.0.0.421-web",
		"biz_trace_id": randHex(8), "device_id": c.DeviceID, "iid": "0", "version_code": "1.1.31",
		"device_platform": "PC", "is_from_iesaccountsaas": "1", "is_new_login": "1",
	}
}

// paramCanonicalOrder 浏览器发包时的固定参数顺序（取自真机 HAR）。
// Go 的 map 迭代顺序随机，必须按此定序，否则每次请求参数顺序都变、
// a_bogus/服务端风控对不上，导致二维码请求异常。
var paramCanonicalOrder = map[string]int{
	"passport_jssdk_version": 0, "passport_jssdk_type": 1, "is_from_ttaccountsdk": 2,
	"aid": 3, "language": 4, "account_app_language": 5, "ts": 6,
	"next": 7, "need_logo": 8, "need_short_url": 9, "is_new_login": 10,
	"is_from_iesaccountsaas": 11, "account_sdk_source": 12, "account_sdk_source_info": 13,
	"p_js_v": 14, "p_js_t": 15, "p_zt": 16, "p_ver": 17, "request_host": 18, "p_bd": 19,
	"biz_trace_id": 20, "new_authn_sdk_version": 21,
	"device_id": 22, "iid": 23, "version_code": 24, "device_platform": 25,
	// 尾部签名参数固定压在最后：sign, qs, msToken, a_bogus
	"sign": 100, "qs": 101, "msToken": 102, "a_bogus": 103,
}

// orderKeys 按 canonical 顺序排序；未收录的 key 排在已知 key 之后、彼此按字典序。
func orderKeys(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		oi, iok := paramCanonicalOrder[keys[i]]
		oj, jok := paramCanonicalOrder[keys[j]]
		if iok && jok {
			return oi < oj
		}
		if iok != jok {
			return iok // 已知的排前面
		}
		return keys[i] < keys[j]
	})
}

func encodeKV(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	orderKeys(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + url.QueryEscape(m[k])
	}
	return strings.Join(parts, "&")
}

// call 发一个已签名的 passport 请求，返回解析后的 JSON。
func (c *Client) call(path string, queryExtra, body map[string]string, lite bool) (map[string]any, error) {
	base := c.normalBase()
	if lite {
		base = c.liteBase()
	}
	query := map[string]string{}
	for k, v := range base {
		query[k] = v
	}
	for k, v := range queryExtra {
		query[k] = v
	}
	if !lite {
		s, qs := sign.SignParams(query, body)
		query["sign"] = s
		query["qs"] = qs
	}
	query["msToken"] = sign.MsToken(128)

	bodyStr := encodeKV(body)
	queryStr := encodeKV(query)
	query["a_bogus"] = abogus.GetABogus(queryStr, bodyStr, c.UA, nowMs())
	fullURL := "https://imdesktop.douyin.com" + path + "?" + queryStr + "&a_bogus=" + url.QueryEscape(query["a_bogus"])

	method := "GET"
	var reqBody io.Reader
	if body != nil {
		method = "POST"
		reqBody = strings.NewReader(bodyStr)
	}
	req, err := http.NewRequest(method, fullURL, reqBody)
	if err != nil {
		return nil, err
	}
// bd-ticket-guard-iteration-version: 2
// bd-ticket-guard-ree-public-key: BEPhQJtcnGrFIlCf8/m+Boe2kyBwe7Wj0hKUVpdDZlj1Dbb4qkcqtSzxGD4eaO6mc4aG9alH1Ka95D1e1ngTKJg=
// bd-ticket-guard-server-cert-sn: 533240336124694022040808462028007165443034493949
// bd-ticket-guard-version: 2
// referer: https://imdesktop.douyin.com
// sec-ch-ua: "Not.A/Brand";v="99", "Chromium";v="136"
// sec-ch-ua-mobile: ?0
// sec-ch-ua-platform: "Windows"
// x-tt-passport-aid-sign: 437536ae85fd28413d036ecf7bf60798421979bdc1fcc15a493474d3bacfb525
// x-tt-passport-csrf-token: 
// x-tt-passport-trace-id: 81c3e95b
// x-tt-passport-verify-portrait: 41918735-2cb8-47d6-a412-9f970bb8410d.login
// priority: u=1, i
	req.Header.Set("bd-ticket-guard-version", "2")
	req.Header.Set("bd-ticket-guard-iteration-version", "2")
	req.Header.Set("bd-ticket-guard-ree-public-key", "BEPhQJtcnGrFIlCf8/m+Boe2kyBwe7Wj0hKUVpdDZlj1Dbb4qkcqtSzxGD4eaO6mc4aG9alH1Ka95D1e1ngTKJg=")
	req.Header.Set("bd-ticket-guard-server-cert-sn", "533240336124694022040808462028007165443034493949")
	req.Header.Set("x-tt-passport-aid-sign", "437536ae85fd28413d036ecf7bf60798421979bdc1fcc15a493474d3bacfb525")
	req.Header.Set("x-tt-passport-csrf-token", "")
	req.Header.Set("x-tt-passport-trace-id", "81c3e95b")
	req.Header.Set("x-tt-passport-verify-portrait", "41918735-2cb8-47d6-a412-9f970bb8410d.login")
	req.Header.Set("User-Agent", c.UA)
	req.Header.Set("Referer", "https://imdesktop.douyin.com")
	// req.Header.Set("Origin", "https://imdesktop.douyin.com")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	if ck := c.Jar.Header(); ck != "" {
		req.Header.Set("Cookie", ck)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	c.Jar.Update(res)
	data, _ := io.ReadAll(res.Body)
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return map[string]any{"_raw": string(data), "_status": res.StatusCode}, nil
	}
	return out, nil
}

// ttwidCheck 拿设备追踪 cookie（登录前置）。
func (c *Client) ttwidCheck() {
	payload, _ := json.Marshal(map[string]any{
		"aid": 339757, "service": "imdesktop.douyin.com", "unionHost": "https://ttwid.bytedance.com",
		"host": "https://imdesktop.douyin.com", "union": false, "needFid": false, "fid": "", "migrate_priority": 0,
	})
	req, _ := http.NewRequest("POST", "https://imdesktop.douyin.com/ttwid/check/", bytes.NewReader(payload))
	req.Header.Set("User-Agent", c.UA)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://imdesktop.douyin.com")
	// req.Header.Set("Origin", "https://imdesktop.douyin.com")
	if ck := c.Jar.Header(); ck != "" {
		req.Header.Set("Cookie", ck)
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	c.Jar.Update(res)
	_, _ = io.Copy(io.Discard, res.Body)
}

```

### `internal/login/device.go`

```go
package login

import (
	"crypto/rand"
	"strings"
)

// GenDeviceID 生成随机 device_id：324 开头 + 7 位随机数字（共 10 位）。
func GenDeviceID() string {
	var sb strings.Builder
	sb.WriteString("324")
	b := make([]byte, 7)
	_, _ = rand.Read(b)
	for _, x := range b {
		sb.WriteByte('0' + x%10)
	}
	return sb.String()
}

```

### `internal/login/fingerprint.go`

```go
package login

import (
	"encoding/json"

	"gobot/internal/sign"
)

// buildFingerprint 生成 account_sdk_source_info（xor5(JSON)）。
// 内容是一份稳定合理的 Windows+Chromium 指纹；sign 会覆盖它，值本身服务端只要能解码即可。
func buildFingerprint(deviceID string) string {
	info := map[string]any{
		"hardwareConcurrency": 8,
		"webdriver":           false,
		"chromedriver":        false,
		"shelldriver":         false,
		"plugins":             5,
		"permissions":         []any{map[string]any{"name": "notifications", "state": "granted"}},
		"innerHeight":         484,
		"innerWidth":          726,
		"outerHeight":         484,
		"outerWidth":          726,
		"stoargeStatus": map[string]any{
			"indexedDB": map[string]any{
				"idb": "object", "open": "function", "indexedDB": "object",
				"IDBKeyRange": "function", "openDatabase": "function", "isSafari": false, "hasFetch": false,
			},
			"localStorage":       map[string]any{"isSupportLStorage": true, "size": 1993, "write": true},
			"storageQuotaStatus": map[string]any{"usage": 0, "quota": 36104626176, "isPrivate": false},
		},
		"webgl": map[string]any{
			"vendor":   "Google Inc. (Google)",
			"renderer": "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)",
		},
		"notificationPermission": "granted",
		"performance": map[string]any{
			"timeOrigin":     1787813991280.3,
			"usedJSHeapSize": 18200000,
			"navigationTiming": map[string]any{
				"decodedBodySize": 2527, "entryType": "navigation", "initiatorType": "navigation",
				"name":                 "file:///renderer/login/index.html?window=login&channel=0&guid=" + deviceID,
				"renderBlockingStatus": "non-blocking",
			},
		},
		"request_host":     "",
		"request_pathname": "/renderer/login/index.html",
		"browser":          map[string]any{"t": "7781993187871", "bit_protocol": "false", "bit_helper": false},
	}
	j, _ := json.Marshal(info)
	return sign.Xor5(string(j))
}

```

### `internal/login/helpers.go`

```go
package login

import "strconv"

func jstr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
func jmap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}
func jnumStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatInt(int64(x), 10)
	case int64:
		return strconv.FormatInt(x, 10)
	}
	return ""
}
func jint(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}

```

### `internal/login/probe.go`

```go
package login

// ProbeResult cookie 探测结果。
type ProbeResult struct {
	Alive   bool // 登录态有效
	Expired bool // 明确会话过期（可据此唤起登录）；网络错误不算
	UID     string
	Name    string
	Reason  string
}

// ProbeCookie GET /passport/account/info/v2/：user_id>0 && error_code==0 为活。
func ProbeCookie(cookie, deviceID string) ProbeResult {
	c := NewClient(deviceID, cookie)
	r, err := c.call("/passport/account/info/v2/", nil, nil, false)
	if err != nil {
		return ProbeResult{Reason: "网络错误：" + err.Error()}
	}
	d := jmap(r["data"])
	uid := jnumStr(d["user_id"])
	if uid != "" && uid != "0" && jint(d["error_code"]) == 0 {
		name := jstr(d["screen_name"])
		if name == "" {
			name = jstr(d["name"])
		}
		return ProbeResult{Alive: true, UID: uid, Name: name, Reason: "ok"}
	}
	reason := jstr(d["description"])
	if reason == "" {
		reason = jstr(r["message"])
	}
	if reason == "" {
		reason = "expired"
	}
	return ProbeResult{Expired: true, Reason: reason}
}

```

### `internal/login/qrlogin.go`

```go
package login

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"gobot/internal/sign"
)

const nextURL = "https://www.douyin.com"

// LoginResult 登录结果。
type LoginResult struct {
	Cookie   string
	UID      string
	Name     string
	DeviceID string
}

// Hooks 登录过程回调。
type Hooks struct {
	// OnQrcode 收到二维码。qrContent 是服务端权威 URL（qrcode_index_url，直接编码即可，
	// 不要去解 PNG——goqr 解服务端 PNG 会串位）；pngBase64 是原始 PNG（仅当没有 URL 时兜底）。
	OnQrcode      func(qrContent, pngBase64, token string)
	OnScanned     func(screenName string)
	OnStatus      func(msg string)
	PromptSmsCode func(mobile string) string // 返回用户输入的短信码（明文）
}

// QRLogin 扫码登录。deviceID 为空则新生成。
func QRLogin(hooks Hooks, deviceID string) (*LoginResult, error) {
	if deviceID == "" {
		deviceID = GenDeviceID()
	}
	c := NewClient(deviceID, "")
	c.ttwidCheck()

	qr, err := c.call("/passport/web/get_qrcode/",
		map[string]string{"next": nextURL, "need_logo": "false", "need_short_url": "false"}, nil, false)
	if err != nil {
		return nil, err
	}
	d := jmap(qr["data"])
	qrcode := jstr(d["qrcode"])
	if qrcode == "" || jint(d["error_code"]) != 0 {
		return nil, fmt.Errorf("获取二维码失败: %v", qr)
	}
	token := jstr(d["token"])
	if hooks.OnQrcode != nil {
		hooks.OnQrcode(jstr(d["qrcode_index_url"]), qrcode, token)
	}

	expireAt := time.Now().Add(180 * time.Second)
	if et := jint(d["expire_time"]); et > 0 {
		expireAt = time.Unix(int64(et), 0)
	}
	baseBody := map[string]string{
		"need_logo": "false", "need_short_url": "false", "is_frontier": "true",
		"token": token, "is_new_login": "1", "next": nextURL,
	}
	extraBody := map[string]string{}
	scanned, mfaDone := false, false

	for time.Now().Before(expireAt) {
		body := map[string]string{}
		for k, v := range baseBody {
			body[k] = v
		}
		for k, v := range extraBody {
			body[k] = v
		}
		r, err := c.call("/passport/web/check_qrconnect/", nil, body, false)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		dd := jmap(r["data"])
		if !mfaDone && (jstr(dd["account_flow"]) == "verify" || dd["biz_params"] != nil) {
			if err := c.doMfa(dd, hooks); err != nil {
				return nil, err
			}
			extraBody = pickBizParams(jmap(dd["biz_params"]))
			mfaDone = true
			continue
		}
		switch jstr(dd["status"]) {
		case "scanned":
			if !scanned {
				scanned = true
				if hooks.OnScanned != nil {
					hooks.OnScanned(jstr(jmap(dd["scan_user_info"])["screen_name"]))
				}
			}
		case "confirmed":
			ud := jmap(dd["user_data"])
			name := jstr(ud["screen_name"])
			if name == "" {
				name = jstr(ud["name"])
			}
			if info, e := c.call("/passport/account/info/v2/", nil, nil, false); e == nil {
				id := jmap(info["data"])
				if n := jstr(id["screen_name"]); n != "" {
					name = n
				} else if n2 := jstr(id["name"]); n2 != "" {
					name = n2
				}
			}
			cookie := c.Jar.Header()
			if !strings.Contains(cookie, "sessionid") {
				return nil, errors.New("已确认但未拿到 sessionid")
			}
			uid := jnumStr(ud["user_id_str"])
			if uid == "" {
				uid = jnumStr(ud["user_id"])
			}
			return &LoginResult{Cookie: cookie, UID: uid, Name: name, DeviceID: deviceID}, nil
		}
		time.Sleep(2 * time.Second)
	}
	return nil, errors.New("二维码已过期或超时，请重试")
}

func pickBizParams(bp map[string]any) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"passport_mfa_retry_tag", "std_verify_flow_id", "std_verify_scene",
		"std_verify_template", "std_verify_token", "std_verify_type", "std_verify_way"} {
		if v, ok := bp[k]; ok {
			out[k] = jstr(v)
		}
	}
	return out
}

func (c *Client) doMfa(d map[string]any, hooks Hooks) error {
	if hooks.PromptSmsCode == nil {
		return errors.New("触发短信二次验证，但未提供输入回调")
	}
	bp := jmap(d["biz_params"])
	cp := jmap(d["common_params"])
	pick := func(m map[string]any, k, def string) string {
		if v := jstr(m[k]); v != "" {
			return v
		}
		return def
	}
	mfa := map[string]string{
		"mix_mode": "1", "type": "3737", "encrypt_uid": jstr(d["encrypt_uid"]), "verify_ticket": "",
		"copywriting_key":          pick(cp, "copywriting_key", "qr_connect"),
		"ies_safety_diversion_tag": pick(cp, "ies_safety_diversion_tag", "mfa"),
		"new_verify_flow":          jstr(cp["new_verify_flow"]),
		"std_verify_flow_id":       pick(bp, "std_verify_flow_id", jstr(cp["std_verify_flow_id"])),
		"std_verify_scene":         pick(bp, "std_verify_scene", "account_login"),
		"std_verify_template":      pick(bp, "std_verify_template", "ato"),
		"std_verify_token":         pick(bp, "std_verify_token", jstr(cp["std_verify_token"])),
		"std_verify_type":          pick(bp, "std_verify_type", "MFA"),
		"std_verify_way":           "mobile_sms_verify",
	}
	withTail := func(extra map[string]string) map[string]string {
		b := map[string]string{}
		for k, v := range mfa {
			b[k] = v
		}
		for k, v := range extra {
			b[k] = v
		}
		b["aid"] = "339757"
		b["new_authn_sdk_version"] = "1.0.0.421-web"
		return b
	}

	sc, err := c.call("/passport/web/send_code/", nil, withTail(map[string]string{"is6Digits": "1"}), true)
	if err != nil {
		return err
	}
	mobile := jstr(jmap(sc["data"])["mobile"])
	if hooks.OnStatus != nil {
		hooks.OnStatus("已向 " + mobile + " 发送短信验证码")
	}
	code := strings.TrimSpace(hooks.PromptSmsCode(mobile))
	vc, err := c.call("/passport/web/validate_code/", nil, withTail(map[string]string{"code": sign.CodeEncrypt(code)}), true)
	if err != nil {
		return err
	}
	if jstr(jmap(vc["data"])["ticket"]) == "" {
		return fmt.Errorf("短信验证失败: %v", vc)
	}
	if hooks.OnStatus != nil {
		hooks.OnStatus("短信验证通过")
	}
	return nil
}

```

### `internal/login/smslogin.go`

```go
package login

import (
	"errors"
	"fmt"
	"strings"

	"gobot/internal/sign"
)

// SMSLogin 手机号 + 短信验证码登录。deviceID 为空则新生成。
//
// mobile/code 都用 code_encrypt（Xor5+hex，见 sign.CodeEncrypt）加密；其余签名参数
// （sign/qs/msToken/a_bogus/account_sdk_source_info）与扫码登录同源，都由 c.call 统一生成，
// 请求头也与扫码登录一致。流程：send_code 发码 → 回调取码 → sms_login 换 cookie。
func SMSLogin(mobile string, hooks Hooks, deviceID string) (*LoginResult, error) {
	m := formatMobile(mobile)
	if m == "" {
		return nil, errors.New("手机号为空")
	}
	if hooks.PromptSmsCode == nil {
		return nil, errors.New("未提供短信验证码输入回调")
	}
	if deviceID == "" {
		deviceID = GenDeviceID()
	}
	c := NewClient(deviceID, "")
	c.ttwidCheck()

	encMobile := sign.CodeEncrypt(m)

	// 1) 发送验证码：type=24（手机验证码登录场景），is6Digits=1 六位码
	sc, err := c.call("/passport/web/send_code/", nil, map[string]string{
		"mix_mode":       "1",
		"mobile":         encMobile,
		"type":           sign.CodeEncrypt("24"),
		"is6Digits":      "1",
		"fixed_mix_mode": "1",
	}, false)
	if err != nil {
		return nil, err
	}
	if jstr(sc["message"]) != "success" {
		return nil, fmt.Errorf("发送验证码失败：%s", errDesc(sc))
	}
	shown := jstr(jmap(sc["data"])["mobile"]) // 服务端回的打码号，如 192******23
	if shown == "" {
		shown = m
	}
	if hooks.OnStatus != nil {
		hooks.OnStatus("已向 " + shown + " 发送短信验证码")
	}

	code := strings.TrimSpace(hooks.PromptSmsCode(shown))
	if code == "" {
		return nil, errors.New("验证码为空")
	}

	// 2) 验证码登录：成功后响应 Set-Cookie 带 sessionid
	lg, err := c.call("/passport/web/sms_login/", nil, map[string]string{
		"service":        nextURL,
		"mix_mode":       "1",
		"mobile":         encMobile,
		"code":           sign.CodeEncrypt(code),
		"fixed_mix_mode": "1",
		"login_only":     "true",
	}, false)
	if err != nil {
		return nil, err
	}
	if jstr(lg["message"]) != "success" {
		return nil, fmt.Errorf("验证码登录失败：%s", errDesc(lg))
	}
	cookie := c.Jar.Header()
	if !strings.Contains(cookie, "sessionid") {
		return nil, errors.New("登录成功但未拿到 sessionid")
	}
	ud := jmap(lg["data"])
	uid := jnumStr(ud["user_id_str"])
	if uid == "" {
		uid = jnumStr(ud["user_id"])
	}
	name := jstr(ud["name"])
	if sn := jstr(ud["screen_name"]); sn != "" {
		name = sn
	}
	return &LoginResult{Cookie: cookie, UID: uid, Name: name, DeviceID: deviceID}, nil
}

// formatMobile 归一成 "+86 <号码>"（服务端要求国家码与号码间有一个空格）。
// 已带 +86 的规整空格；其它 + 开头的国家码原样返回（调用方自证格式）。
func formatMobile(raw string) string {
	raw = strings.NewReplacer(" ", "", "-", "", "(", "", ")", "").Replace(strings.TrimSpace(raw))
	switch {
	case raw == "":
		return ""
	case strings.HasPrefix(raw, "+86"):
		return "+86 " + raw[3:]
	case strings.HasPrefix(raw, "+"):
		return raw
	case strings.HasPrefix(raw, "86") && len(raw) > 11:
		return "+86 " + raw[2:]
	default:
		return "+86 " + raw
	}
}

// errDesc 从 passport 响应里抽出可读错误信息。
func errDesc(r map[string]any) string {
	d := jmap(r["data"])
	if s := jstr(d["description"]); s != "" {
		return s
	}
	if s := jstr(d["error_str"]); s != "" {
		return s
	}
	if s := jstr(r["message"]); s != "" {
		return s
	}
	return fmt.Sprintf("%v", r)
}

```


## G. 二维码 (internal/qr)

### `internal/qr/qr.go`

```go
// Package qr 二维码：解 get_qrcode 的 base64 PNG 拿内容，再渲染成紧凑的终端二维码。
//
// 终端字符格宽高约 1:2（高是宽的两倍），所以要让"模块"显示成正方形，
// 一个字符格必须横向放的模块数 : 纵向放的模块数 = 1:2：
//   - 半块 ▀▄█（1 模块宽 × 2 模块高/格）：模块正方、实心块，扫码最稳（默认）。
//   - 盲文点阵（2 模块宽 × 4 模块高/格）：模块仍正方、更小，但点阵有缝隙，很多扫码器读不了。
//
// 登录二维码内容是 333 字符的长 URL(≈65 模块)，实心块下宽度就得 ≈65 列，这是内容决定的、压不动。
// 默认半块；GOBOT_QR=braille 换盲文（更小，扫码器能读再用）。
package qr

import (
	"bytes"
	"encoding/base64"
	"errors"
	"image/png"
	"os"
	"strings"

	"github.com/liyue201/goqr"
	"rsc.io/qr"
)

// DecodeQRPng 解出二维码内容（URL/字符串）。
func DecodeQRPng(pngBase64 string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(pngBase64)
	if err != nil {
		return "", err
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	codes, err := goqr.Recognize(img)
	if err != nil {
		return "", err
	}
	if len(codes) == 0 {
		return "", errors.New("未识别到二维码")
	}
	return string(codes[0].Payload), nil
}

// RenderTerminal 内容 → 紧凑终端二维码（ECC=L）。默认半块（实心、可扫），GOBOT_QR=braille 换盲文。
func RenderTerminal(content string) (string, error) {
	code, err := qr.Encode(content, qr.L)
	if err != nil {
		return "", err
	}
	if strings.EqualFold(os.Getenv("GOBOT_QR"), "braille") {
		return renderBraille(code), nil
	}
	return renderHalf(code), nil
}

// darkFn 返回一个判定：给定含静默区坐标是否为暗模块（越界/静默区=亮）。
func darkFn(code *qr.Code, quiet int) func(x, y int) bool {
	n := code.Size
	return func(x, y int) bool {
		x -= quiet
		y -= quiet
		if x < 0 || y < 0 || x >= n || y >= n {
			return false
		}
		return code.Black(x, y)
	}
}

// renderHalf 半块渲染：1 模块宽 × 2 模块高/字符，暗=实心。模块正方、实心，最稳。
func renderHalf(code *qr.Code) string {
	const quiet = 2
	dim := code.Size + quiet*2
	dark := darkFn(code, quiet)
	var b strings.Builder
	for y := 0; y < dim; y += 2 {
		for x := 0; x < dim; x++ {
			top, bot := dark(x, y), dark(x, y+1)
			switch {
			case top && bot:
				b.WriteRune('█')
			case top:
				b.WriteRune('▀')
			case bot:
				b.WriteRune('▄')
			default:
				b.WriteByte(' ')
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// renderBraille 盲文点阵：2 模块宽 × 4 模块高/字符（U+2800 起）。模块正方、尺寸最小。
// 盲文点位：dx∈{0,1}, dy∈{0..3} → bit
//
//	(0,0)=1  (1,0)=8
//	(0,1)=2  (1,1)=16
//	(0,2)=4  (1,2)=32
//	(0,3)=64 (1,3)=128
func renderBraille(code *qr.Code) string {
	const quiet = 3
	dim := code.Size + quiet*2
	dark := darkFn(code, quiet)
	var b strings.Builder
	for y := 0; y < dim; y += 4 {
		for x := 0; x < dim; x += 2 {
			var pat int
			if dark(x, y) {
				pat |= 0x01
			}
			if dark(x, y+1) {
				pat |= 0x02
			}
			if dark(x, y+2) {
				pat |= 0x04
			}
			if dark(x+1, y) {
				pat |= 0x08
			}
			if dark(x+1, y+1) {
				pat |= 0x10
			}
			if dark(x+1, y+2) {
				pat |= 0x20
			}
			if dark(x, y+3) {
				pat |= 0x40
			}
			if dark(x+1, y+3) {
				pat |= 0x80
			}
			if pat == 0 {
				b.WriteByte(' ') // 亮区用空格，保证静默区干净
			} else {
				b.WriteRune(rune(0x2800 + pat))
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// RenderPNG 把内容编码成 PNG 图片字节（含静默区，每模块 8px），用于存本地直接扫图。
func RenderPNG(content string) ([]byte, error) {
	code, err := qr.Encode(content, qr.L)
	if err != nil {
		return nil, err
	}
	code.Scale = 8
	return code.PNG(), nil
}

// PngToTerminalQR PNG(base64) → 终端二维码串。
func PngToTerminalQR(pngBase64 string) (string, error) {
	content, err := DecodeQRPng(pngBase64)
	if err != nil {
		return "", err
	}
	return RenderTerminal(content)
}

```


## H. IM 引擎·核心 (internal/engine)

### `internal/engine/proto.go`

```go
// Package engine IM（frontier-aweme）引擎：WebSocket 连接 + protobuf 组解包 + 消息收发。
// 1:1 转译自 TS 版 personal_ck/ImClient.ts + WsConnection.ts。
package engine

import (
	"encoding/base64"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ProtoField 宽松 protobuf 字段（imapi 无公开 .proto，按 wire type 猜）。
// Type 取值：varint / string / message / bytes。
type ProtoField struct {
	Field  int
	Type   string
	VUint  uint64       // Type==varint
	VStr   string       // Type==string
	VMsg   []ProtoField // Type==message
	VBytes []byte       // Type==bytes
}

// -- 编码 -------------------------------------------------------------------

// encodeVarint 无符号 varint。
func encodeVarint(v uint64) []byte {
	out := make([]byte, 0, 10)
	for v > 0x7f {
		out = append(out, byte(v&0x7f)|0x80)
		v >>= 7
	}
	return append(out, byte(v&0x7f))
}

func encodeTag(fieldNum, wireType int) []byte {
	return encodeVarint(uint64(fieldNum<<3) | uint64(wireType))
}

func encodeFieldVarint(fieldNum int, value uint64) []byte {
	return append(encodeTag(fieldNum, 0), encodeVarint(value)...)
}

func encodeLenDelim(fieldNum int, data []byte) []byte {
	out := encodeTag(fieldNum, 2)
	out = append(out, encodeVarint(uint64(len(data)))...)
	return append(out, data...)
}

func encodeLenDelimS(fieldNum int, s string) []byte {
	return encodeLenDelim(fieldNum, []byte(s))
}

func encodeKvPair(fieldNum int, key, value string) []byte {
	kv := append(encodeLenDelimS(1, key), encodeLenDelimS(2, value)...)
	return encodeLenDelim(fieldNum, kv)
}

func concat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// -- 解码 -------------------------------------------------------------------

// decodeVarintAt 从 pos 读一个 varint，返回值与新的 pos；越界/超 64bit 返回 ok=false。
func decodeVarintAt(data []byte, pos int) (uint64, int, bool) {
	var result uint64
	var shift uint
	n := len(data)
	for pos < n {
		if shift >= 64 {
			return 0, pos, false
		}
		b := data[pos]
		pos++
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, pos, true
		}
		shift += 7
	}
	return result, pos, true
}

// tryUtf8 能安全当文本就返回 (s,true)；含控制字符或非法 UTF-8 返回 ("",false)。
func tryUtf8(buf []byte) (string, bool) {
	if !utf8.Valid(buf) {
		return "", false
	}
	for _, b := range buf {
		if b < 0x20 && b != 0x09 && b != 0x0a && b != 0x0d {
			return "", false
		}
	}
	return string(buf), true
}

// decodeProtobuf 宽松解码：像 JSON 的当字符串，其余尝试递归当子消息。
func decodeProtobuf(data []byte, depth int) []ProtoField {
	var fields []ProtoField
	pos := 0
	n := len(data)

	for pos < n {
		tag, np, ok := decodeVarintAt(data, pos)
		if !ok {
			break
		}
		pos = np
		fieldNum := int(tag >> 3)
		wireType := int(tag & 0x07)
		if fieldNum == 0 {
			break
		}

		switch wireType {
		case 0:
			val, np, ok := decodeVarintAt(data, pos)
			if !ok {
				return fields
			}
			pos = np
			fields = append(fields, ProtoField{Field: fieldNum, Type: "varint", VUint: val})
		case 2:
			lengthBig, np, ok := decodeVarintAt(data, pos)
			if !ok {
				return fields
			}
			pos = np
			length := int(lengthBig)
			if length < 0 || pos+length > n {
				return fields
			}
			raw := data[pos : pos+length]
			pos += length

			text, textOk := tryUtf8(raw)
			trimmed := ""
			if textOk {
				trimmed = strings.TrimLeft(text, " \t\n\r\f\v")
			}
			looksJson := textOk && trimmed != "" && (trimmed[0] == '{' || trimmed[0] == '[')
			// sec_uid("MS4...")、URL、纯数字、uuid/hex 令牌(client_message_id 等)都是可打印标量串，
			// 字节常能误当嵌套 message 解开(数字全是合法 varint、uuid 随机命中)，硬判为字符串。
			looksToken := textOk && (strings.HasPrefix(trimmed, "MS4") ||
				strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") ||
				isDigits(trimmed) || looksHexToken(trimmed))

			if looksJson || looksToken {
				fields = append(fields, ProtoField{Field: fieldNum, Type: "string", VStr: text})
			} else {
				var nested []ProtoField
				if depth < 8 {
					nested = decodeProtobuf(raw, depth+1)
				}
				if len(nested) > 0 {
					fields = append(fields, ProtoField{Field: fieldNum, Type: "message", VMsg: nested})
				} else if textOk {
					fields = append(fields, ProtoField{Field: fieldNum, Type: "string", VStr: text})
				} else {
					fields = append(fields, ProtoField{Field: fieldNum, Type: "bytes", VBytes: append([]byte(nil), raw...)})
				}
			}
		case 1:
			pos += 8
		case 5:
			pos += 4
		default:
			return fields
		}
	}
	return fields
}

// decodeTop 顶层解码（TS 侧有 WeakMap 缓存，Go 侧每次现解，语义一致）。
func decodeTop(payload []byte) []ProtoField {
	return decodeProtobuf(payload, 0)
}

// DecodeToTree 把原始 protobuf 解成便于 JSON 展示的树（调试 / 逆向新消息类型用）。
// 每个字段 {f: 字段号, t: 类型, v: 值}；varint 转字符串避免大数丢精度，bytes 转 base64。
func DecodeToTree(payload []byte) []map[string]any {
	return fieldsToTree(decodeTop(payload))
}

func fieldsToTree(fs []ProtoField) []map[string]any {
	out := make([]map[string]any, 0, len(fs))
	for _, f := range fs {
		m := map[string]any{"f": f.Field, "t": f.Type}
		switch f.Type {
		case "varint":
			m["v"] = strconv.FormatUint(f.VUint, 10)
		case "string":
			m["v"] = f.VStr
		case "message":
			m["v"] = fieldsToTree(f.VMsg)
		case "bytes":
			m["v"] = base64.StdEncoding.EncodeToString(f.VBytes)
		}
		out = append(out, m)
	}
	return out
}

// searchPath 沿字段号路径找 varint，找不到返回 ok=false。
func searchPath(fields []ProtoField, path []int) (uint64, bool) {
	for _, f := range fields {
		if f.Field != path[0] {
			continue
		}
		if len(path) == 1 {
			if f.Type == "varint" {
				return f.VUint, true
			}
			return 0, false
		}
		if f.Type == "message" {
			if r, ok := searchPath(f.VMsg, path[1:]); ok {
				return r, true
			}
		}
	}
	return 0, false
}

// -- JS 兼容小工具 ----------------------------------------------------------

func itoa(n int) string { return strconv.Itoa(n) }

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// looksHexToken：长度≥8 且只含 [0-9a-fA-F-]（uuid / md5 / hex id）。这类标量串会被裸解码器
// 随机误当嵌套 message，硬判为字符串。真正的嵌套 message 含 tag/长度控制字节，不会全落此集。
func looksHexToken(s string) bool {
	if len(s) < 8 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-') {
			return false
		}
	}
	return true
}

// toInt 宽松取整（对应 helpers.toInt）。
func toInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case bool:
		if x {
			return 1
		}
		return 0
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}

// toStr 宽松取串（对应 helpers.toStr）。
func toStr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "1"
		}
		return ""
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

```

### `internal/engine/wsconn.go`

```go
package engine

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
)

// WsProxy 出口代理（socks5 默认，或 http/https）。
type WsProxy struct {
	Host, User, Pass string
	Port             int
	Scheme           string // socks5 / http / https
}

const maxFrameBytes = 33_554_432

// WsConn 对应 TS WsConnection：连接（可走代理）+ receive(timeout) 拉模型收包 + send/ping/close。
type WsConn struct {
	ws       *websocket.Conn
	msgs     chan []byte
	done     chan struct{}
	writeMu  sync.Mutex
	closeMu  sync.Mutex
	closed   atomic.Bool
	closeErr atomic.Value // error
}

// wsConnect 建立连接；握手失败抛错。headers 里的 Sec-WebSocket-Protocol 会转成子协议。
func wsConnect(rawURL string, headers map[string]string, px *WsProxy, handshakeTimeout time.Duration) (*WsConn, error) {
	if handshakeTimeout <= 0 {
		handshakeTimeout = 30 * time.Second
	}

	h := http.Header{}
	var protocols []string
	for k, v := range headers {
		lower := strings.ToLower(k)
		switch lower {
		case "host", "upgrade", "connection", "sec-websocket-key", "sec-websocket-version":
			// 由 gorilla 自己生成
		case "sec-websocket-protocol":
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" {
					protocols = append(protocols, p)
				}
			}
		default:
			h.Set(k, v)
		}
	}

	d := websocket.Dialer{
		Subprotocols:      protocols,
		HandshakeTimeout:  handshakeTimeout,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		EnableCompression: false,
		ReadBufferSize:    32 * 1024,
		WriteBufferSize:   32 * 1024,
	}
	if err := applyProxy(&d, px); err != nil {
		return nil, err
	}

	ws, resp, err := d.Dial(rawURL, h)
	if err != nil {
		if resp != nil {
			return nil, errors.New("WebSocket handshake failed: HTTP " + resp.Status)
		}
		return nil, err
	}
	ws.SetReadLimit(maxFrameBytes)

	c := &WsConn{ws: ws, msgs: make(chan []byte, 256), done: make(chan struct{})}
	go c.reader()
	return c, nil
}

func applyProxy(d *websocket.Dialer, px *WsProxy) error {
	if px == nil || px.Host == "" {
		// 无显式代理时跟随 HTTP(S)_PROXY / ALL_PROXY / NO_PROXY 环境变量，
		// 让 WS 和 HTTP 一样能经终端代理抓包分析（TLS 已 InsecureSkipVerify，MITM 直通）。
		d.Proxy = http.ProxyFromEnvironment
		return nil
	}
	scheme := px.Scheme
	if scheme == "" {
		scheme = "socks5"
	}
	addr := net.JoinHostPort(px.Host, itoa(px.Port))

	if scheme == "http" || scheme == "https" {
		u := &url.URL{Scheme: scheme, Host: addr}
		if px.User != "" {
			u.User = url.UserPassword(px.User, px.Pass)
		}
		d.Proxy = http.ProxyURL(u)
		return nil
	}

	var auth *proxy.Auth
	if px.User != "" {
		auth = &proxy.Auth{User: px.User, Password: px.Pass}
	}
	sd, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
	if err != nil {
		return err
	}
	if cd, ok := sd.(proxy.ContextDialer); ok {
		d.NetDialContext = cd.DialContext
	} else {
		d.NetDial = sd.Dial
	}
	return nil
}

func (c *WsConn) reader() {
	for {
		_, data, err := c.ws.ReadMessage()
		if err != nil {
			c.setClosed(err)
			return
		}
		select {
		case c.msgs <- data:
		case <-c.done:
			return
		}
	}
}

func (c *WsConn) setClosed(err error) {
	if c.closed.CompareAndSwap(false, true) {
		if err == nil {
			err = errors.New("WebSocket connection closed by server")
		}
		c.closeErr.Store(err)
		c.closeMu.Lock()
		close(c.done)
		c.closeMu.Unlock()
	}
}

func (c *WsConn) err() error {
	if v := c.closeErr.Load(); v != nil {
		return v.(error)
	}
	return errors.New("WebSocket socket already closed")
}

// IsOpen 连接是否可用。
func (c *WsConn) IsOpen() bool { return !c.closed.Load() }

// Receive 取一条消息；timeout 到返回 (nil,nil)；连接断开返回错误。
func (c *WsConn) Receive(timeout time.Duration) ([]byte, error) {
	select {
	case m := <-c.msgs:
		return m, nil
	default:
	}
	if c.closed.Load() {
		// 断开前也许还有已入队的消息
		select {
		case m := <-c.msgs:
			return m, nil
		default:
		}
		return nil, c.err()
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case m := <-c.msgs:
		return m, nil
	case <-t.C:
		return nil, nil
	case <-c.done:
		select {
		case m := <-c.msgs:
			return m, nil
		default:
		}
		return nil, c.err()
	}
}

// Send 发送二进制帧。
func (c *WsConn) Send(data []byte) error {
	if c.closed.Load() {
		return c.err()
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.ws.WriteMessage(websocket.BinaryMessage, data)
}

// Ping 发送 WebSocket ping 控制帧（失败静默，下次 Receive 会感知断开）。
func (c *WsConn) Ping() {
	if c.closed.Load() {
		return
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
}

// Close 关闭连接。
func (c *WsConn) Close() {
	c.setClosed(errors.New("closed by client"))
	c.writeMu.Lock()
	_ = c.ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	c.writeMu.Unlock()
	_ = c.ws.Close()
}

```

### `internal/engine/client.go`

```go
package engine

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// -- 常量（来自 ImClient.ts）------------------------------------------------

const (
	androidSendWsBase = "wss://frontier-aweme-lf-ipainner.amemv.com/ws/v2"

	akFpID   = "9"
	akAppKey = "e1bd35ec9db7b8d846de66ed140b1ad9"
	akSalt   = "f8a69f1719916z"

	awemeAID               = "1128"
	awemeVersionCode       = "280400"
	awemeVersionName       = "28.4.0"
	awemeUpdateVersionCode = "28409900"
	awemeChannel           = "douyinweb1_64"
	awemeDeviceType        = "24031PN0DC"
	awemeDeviceBrand       = "XIAOMI"
	awemeOSVersion         = "14"
	awemeOSAPI             = "34"
	awemeAppName           = "aweme"
	awemeAppPackage        = "com.ss.android.ugc.aweme"
	awemeUA                = "okhttp/3.12.1 com.ss.android.ugc.aweme/280400"

	// WS 发送(安卓 frontier cmd100 内层)专用，逆自 TS ImClient.buildAndroidCmd100Inner。
	awemeSDKVersion   = "5.0.3.0-rc.11-SNAPSHOT"
	awemeBuildNumber2 = "5030"
)

// -- 对外类型 ---------------------------------------------------------------

// ImImage 图片消息（aweType 2702）资源，供下载 + AES-256-GCM(key=skey) 解密。
type ImImage struct {
	Skey          string
	Oid           string
	Md5           string
	DataSize      int
	CoverWidth    int
	CoverHeight   int
	OriginURLList []string
	LargeURLList  []string
	MediumURLList []string
	ThumbURLList  []string
}

// PickURL 取一个可用的原图 URL（优先 origin，其次 large/medium/thumb）。
func (im *ImImage) PickURL() string {
	for _, l := range [][]string{im.OriginURLList, im.LargeURLList, im.MediumURLList, im.ThumbURLList} {
		if len(l) > 0 {
			return l[0]
		}
	}
	return ""
}

// ImVideo 视频消息资源。视频流用 tkey 走 batch_play_info 换可播 URL；poster 是封面图（可解密）。
type ImVideo struct {
	Tkey      string
	Skey      string
	Md5       string
	Width     int
	Height    int
	CheckPics []string
	Poster    *ImImage
}

// ImEmoji 表情消息（aweType 507）。url 是明文图地址（im-resource），可直接展示，无需解密。
type ImEmoji struct {
	DisplayName string
	ImageType   string
	Width       int
	Height      int
	URL         string
	StickerID   string
}

// IncomingMessage 投递给上层的一条收到的消息。
type IncomingMessage struct {
	ConvID    string
	IsGroup   bool // 群聊(conv_id 为纯数字)则 true；私信(0:1:小:大)为 false
	SenderID  string
	SenderMs4 string
	Text      string
	AweType   int
	Image     *ImImage
	Video     *ImVideo
	Emoji     *ImEmoji
	Direction string // 目前只投递 recv
}

// Client frontier-aweme IM 客户端（单账号）。
type Client struct {
	Cookie      string
	CkUid       string // 账号 user_id，既作 selfUid 也作 device_id
	DeviceID    string
	Proxy       *WsProxy
	SendChannel string       // 发送通道："ws" 走安卓 frontier WS，其余(默认)走 HTTP imapi
	OnRaw       func([]byte) // 可选：每收到一帧原始 payload 就回调（调试用）
	seq         int64
	shortIDs    sync.Map // convID(string) -> conv_short_id(uint64)，从收到的消息里学，发送时回填
}

// resolveShort 发送时若未显式给 short_id，用收包学到的缓存回填。
func (c *Client) resolveShort(convID string, shortID uint64) uint64 {
	if shortID != 0 {
		return shortID
	}
	if v, ok := c.shortIDs.Load(convID); ok {
		return v.(uint64)
	}
	return 0
}

// New 创建客户端。uid 为账号 user_id。
func New(cookie, uid, deviceID string) *Client {
	return &Client{Cookie: cookie, CkUid: strings.TrimSpace(uid), DeviceID: deviceID}
}

func (c *Client) nextSeq() int { return int(atomic.AddInt64(&c.seq, 1)) }

func (c *Client) computeAccessKey(deviceID string) string {
	sum := md5.Sum([]byte(akFpID + akAppKey + deviceID + akSalt))
	return hex.EncodeToString(sum[:])
}

// -- 连接 -------------------------------------------------------------------

// Connect 建立 frontier-aweme 发送/接收连接。
func (c *Client) Connect() (*WsConn, error) {
	if strings.TrimSpace(c.CkUid) == "" {
		return nil, errors.New("发送连接失败：缺少 user_id")
	}
	return c.makeClient(c.buildAndroidSendWsURL())
}

func (c *Client) buildAndroidSendWsURL() string {
	deviceID := c.CkUid
	now := time.Now().Unix()
	params := [][2]string{
		{"aid", awemeAID}, {"fpid", akFpID}, {"sdk_version", "3"}, {"device_id", deviceID}, {"iid", deviceID},
		{"access_key", c.computeAccessKey(deviceID)}, {"pl", "0"}, {"ne", "1"},
		{"version_code", awemeVersionCode}, {"version_name", awemeVersionName}, {"update_version_code", awemeUpdateVersionCode},
		{"platform", "0"}, {"monitor_service_id_list", "[]"}, {"is_background", "0"}, {"ping-interval", "30"},
		{"qos_level", "2"}, {"qos_sdk_version", "2"}, {"ttnet_ignore_offline", "1"}, {"ws_connect_protocol", "0"},
		{"device_platform", "android"}, {"os", "android"}, {"app_name", awemeAppName}, {"package", awemeAppPackage},
		{"channel", awemeChannel}, {"ac", "wifi"}, {"language", "zh"}, {"device_type", awemeDeviceType},
		{"device_brand", awemeDeviceBrand}, {"os_api", awemeOSAPI}, {"os_version", awemeOSVersion},
		{"ts", strconv.FormatInt(now, 10)}, {"_rticket", strconv.FormatInt(now*1000, 10)},
	}
	var sb strings.Builder
	for i, kv := range params {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(kv[0])
		sb.WriteByte('=')
		sb.WriteString(rawURLEncode(kv[1]))
	}
	return androidSendWsBase + "?" + sb.String()
}

func (c *Client) makeClient(wsURL string) (*WsConn, error) {
	headers := map[string]string{
		"User-Agent":             awemeUA,
		"Origin":                 "wss://frontier-aweme-lf-ipainner.amemv.com",
		"Cookie":                 c.Cookie,
		"x-support-qos2":         "1",
		"x-support-ack":          "1",
		"sdk-version":            "2",
		"passport-sdk-version":   "601504",
		"X-SS-DP":                awemeAID,
		"x-tt-store-region":      "cn",
		"x-tt-store-region-src":  "uid",
		"x-bd-kmsv":              "1",
		"Sec-WebSocket-Protocol": "pbbp2",
	}
	cookies := parseCookies(c.Cookie)
	if v, ok := cookies["session_tlb_tag"]; ok {
		headers["session-tlb-tag"] = uriDecode(v)
	}
	if v, ok := cookies["passport_mfa_token"]; ok {
		headers["x-tt-passport-mfa-token"] = uriDecode(v)
	}
	return wsConnect(wsURL, headers, c.Proxy, 30*time.Second)
}

// -- 收发主循环 -------------------------------------------------------------

// RunSession 心跳 + 收包主循环，返回断开原因：stop（被要求停止）或 disconnect（连接断了）。
func (c *Client) RunSession(conn *WsConn, onMessage func(IncomingMessage), shouldStop func() bool) string {
	const heartbeat = 15 * time.Second
	const deadAfter = 40 * time.Second

	var lastRecv atomic.Int64
	lastRecv.Store(time.Now().Unix())
	reason := "disconnect"
	stop := make(chan struct{})
	var once sync.Once
	done := func() { once.Do(func() { close(stop) }) }

	go func() {
		t := time.NewTicker(heartbeat)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				conn.Ping()
				if time.Now().Unix()-lastRecv.Load() > int64(deadAfter/time.Second) {
					done()
					return
				}
			}
		}
	}()

	if shouldStop != nil {
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					if shouldStop() {
						reason = "stop"
						done()
						return
					}
				}
			}
		}()
	}

loop:
	for {
		select {
		case <-stop:
			break loop
		default:
		}
		raw, err := conn.Receive(time.Second)
		if err != nil {
			break
		}
		if raw != nil {
			lastRecv.Store(time.Now().Unix())
		}
		if len(raw) == 0 {
			continue
		}
		if c.OnRaw != nil {
			c.OnRaw(raw)
		}
		c.handleIncoming(raw, onMessage)
	}
	done()
	conn.Close()
	return reason
}

func (c *Client) handleIncoming(raw []byte, onMessage func(IncomingMessage)) {
	items := c.extractChatItems(raw, c.CkUid)
	if len(items) == 0 || onMessage == nil {
		return
	}
	self := strings.TrimSpace(c.CkUid)
	for _, it := range items {
		if it.shortID != 0 && it.convID != "" {
			c.shortIDs.Store(it.convID, it.shortID) // 学会话短 ID，供发送回填
		}
		// 投递全部（recv + sent，带 Direction），由消费侧决定是否要自己发的
		convID := it.convID
		if convID == "" && !strings.HasPrefix(it.text, "[系统]") {
			peer := strings.TrimSpace(it.senderID)
			if isDigits(self) && isDigits(peer) {
				if self == peer {
					convID = "0:1:" + self + ":" + self // 自聊
				} else {
					x, y := self, peer
					if convLess(y, x) {
						x, y = y, x
					}
					convID = "0:1:" + x + ":" + y
				}
			}
		}
		onMessage(IncomingMessage{
			ConvID: convID, IsGroup: isGroupConv(convID), SenderID: it.senderID, SenderMs4: it.senderMs4,
			Text: it.text, AweType: it.aweType, Image: it.image, Video: it.video, Emoji: it.emoji, Direction: it.direction,
		})
	}
}

// BuildConvID 由自己和对方 uid 拼单聊 conv_id（0:1:小:大，按 TS 排序规则）。非法返回 ""。
func BuildConvID(selfUID, peerUID string) string {
	self := strings.TrimSpace(selfUID)
	peer := strings.TrimSpace(peerUID)
	if !isDigits(self) || !isDigits(peer) || self == peer {
		return ""
	}
	x, y := self, peer
	if convLess(y, x) {
		x, y = y, x
	}
	return "0:1:" + x + ":" + y
}

// convLess 复刻 TS 排序：先按长度升序，再字典序。
func convLess(p, q string) bool {
	if len(p) != len(q) {
		return len(p) < len(q)
	}
	return p < q
}

// -- 聊天条目提取（collectChat / parseChatJsonItem）-------------------------

type chatItem struct {
	direction   string
	convID      string
	shortID     uint64
	serverMsgID uint64
	senderID    string
	senderMs4   string
	text        string
	aweType     int
	image       *ImImage
	video       *ImVideo
	emoji       *ImEmoji
}

type parsedItem struct {
	text      string
	aweType   int
	direction string
	image     *ImImage
	video     *ImVideo
	emoji     *ImEmoji
}

func (c *Client) extractChatItems(payload []byte, selfUid string) []chatItem {
	var out []chatItem
	c.collectChat(decodeTop(payload), &out, "", "", "", selfUid)
	if len(out) == 0 {
		c.collectChatFromRawJson(payload, &out, selfUid)
	}
	return out
}

func (c *Client) collectChat(fields []ProtoField, out *[]chatItem, senderID, convID, senderMs4, selfUid string) {
	// pass 1：拿发送者 / 会话 / sec_uid 上下文
	for _, f := range fields {
		if f.Field == 7 && f.Type == "varint" {
			senderID = strconv.FormatUint(f.VUint, 10)
		}
		if f.Field == 7 && f.Type == "string" && isDigits(f.VStr) {
			senderID = f.VStr
		}
		if f.Type == "string" {
			v := f.VStr
			if v != "" && strings.HasPrefix(v, "0:1:") && strings.Count(v, ":") == 3 {
				convID = v
			} else if f.Field == 1 && v != "" && convID == "" {
				convID = v
			}
		}
		if f.Field == 14 && f.Type == "string" && strings.HasPrefix(f.VStr, "MS4") {
			senderMs4 = f.VStr
		}
	}

	// pass 2：抠 JSON 条目
	for _, f := range fields {
		if f.Type == "string" {
			fid := f.Field
			val := f.VStr
			shouldTry := fid == 6 || fid == 8
			if !shouldTry && (strings.Contains(val, `"text"`) || strings.Contains(val, "aweType") || strings.Contains(val, "tkey")) {
				shouldTry = true
			}
			if shouldTry {
				var obj map[string]any
				if json.Unmarshal([]byte(val), &obj) == nil && obj != nil {
					if p, ok := c.parseChatJsonItem(obj, senderID, selfUid); ok {
						*out = append(*out, chatItem{
							direction: p.direction, convID: convID, senderID: senderID,
							senderMs4: senderMs4, text: p.text, aweType: p.aweType,
							image: p.image, video: p.video, emoji: p.emoji,
						})
					}
				}
			}
		}
		if f.Type == "message" {
			c.collectChat(f.VMsg, out, senderID, convID, senderMs4, selfUid)
		}
	}

	var shortID uint64
	for _, path := range [][]int{{8, 6, 500, 5, 5}, {8, 6, 100, 10, 2}, {8, 6, 100, 50, 2}} {
		if v, ok := searchPath(fields, path); ok {
			shortID = v
			break
		}
	}
	serverMsgID, _ := searchPath(fields, []int{8, 6, 500, 5, 3})
	for i := range *out {
		if shortID != 0 && (*out)[i].shortID == 0 {
			(*out)[i].shortID = shortID
		}
		if serverMsgID != 0 && (*out)[i].serverMsgID == 0 {
			(*out)[i].serverMsgID = serverMsgID
		}
	}
}

var reConvID = regexp.MustCompile(`0:1:\d+:\d+`)
var reJSONChunk = regexp.MustCompile(`\{(?:[^{}]|\{[^{}]*\})*\}`)

// collectChatFromRawJson protobuf 解不出条目时的兜底：直接从裸字节抠 JSON 片段。
func (c *Client) collectChatFromRawJson(payload []byte, out *[]chatItem, selfUid string) {
	text := string(payload)
	convID := reConvID.FindString(text)

	seen := map[string]bool{}
	for _, chunk := range reJSONChunk.FindAllString(text, -1) {
		if !strings.Contains(chunk, `"text"`) && !strings.Contains(chunk, "aweType") && !strings.Contains(chunk, "tkey") {
			continue
		}
		var obj map[string]any
		if json.Unmarshal([]byte(chunk), &obj) != nil || obj == nil {
			continue
		}
		p, ok := c.parseChatJsonItem(obj, "", selfUid)
		if !ok {
			continue
		}
		key := p.text + "|" + strconv.Itoa(p.aweType)
		if seen[key] {
			continue
		}
		seen[key] = true
		*out = append(*out, chatItem{
			direction: p.direction, convID: convID, text: p.text, aweType: p.aweType,
			image: p.image, video: p.video, emoji: p.emoji,
		})
	}
}

// parseImageRes 从 resource_url / poster 风格的 map 抠出 ImImage（cover_w/h 从 outer 取）。
func parseImageRes(ru, outer map[string]any) *ImImage {
	skey, _ := ru["skey"].(string)
	if skey == "" {
		return nil
	}
	oid, _ := ru["oid"].(string)
	md5s, _ := ru["md5"].(string)
	return &ImImage{
		Skey: skey, Oid: oid, Md5: md5s,
		DataSize:      toInt(ru["data_size"]),
		CoverWidth:    toInt(outer["cover_width"]),
		CoverHeight:   toInt(outer["cover_height"]),
		OriginURLList: strList(ru["origin_url_list"]),
		LargeURLList:  strList(ru["large_url_list"]),
		MediumURLList: strList(ru["medium_url_list"]),
		ThumbURLList:  strList(ru["thumb_url_list"]),
	}
}

func (c *Client) parseChatJsonItem(obj map[string]any, senderID, selfUid string) (parsedItem, bool) {
	aweType := toInt(obj["aweType"])

	// 先抠图片/视频：这类消息往往没有 text 字段，必须在"文本判空"之前处理，否则会被丢掉。
	var image *ImImage
	if aweType == 2702 {
		if ru, ok := obj["resource_url"].(map[string]any); ok {
			image = parseImageRes(ru, obj)
		}
	}

	// 视频：content 里没有 aweType，靠 video.tkey 识别；poster 是封面图（可解密）。
	var video *ImVideo
	if v, ok := obj["video"].(map[string]any); ok {
		if tkey, _ := v["tkey"].(string); tkey != "" {
			skey, _ := v["skey"].(string)
			md5s, _ := v["md5"].(string)
			video = &ImVideo{
				Tkey: tkey, Skey: skey, Md5: md5s,
				Width: toInt(obj["width"]), Height: toInt(obj["height"]),
				CheckPics: strList(obj["check_pics"]),
			}
			if p, ok := obj["poster"].(map[string]any); ok {
				video.Poster = parseImageRes(p, p)
			}
		}
	}

	// 表情（aweType 507）：往往没有 text 字段，须在"文本判空"前抠出，否则被丢。url 是明文图。
	var emoji *ImEmoji
	if aweType == 507 {
		emoji = parseEmoji(obj)
	}

	// 文本：text > 展示文案 > 表情名/占位
	text, _ := obj["text"].(string)
	if text == "" {
		text = c.parseMessageDisplay(obj)
	}
	if text == "" {
		switch {
		case video != nil:
			text = "[视频]"
		case image != nil:
			text = "[图片]"
		case emoji != nil:
			if emoji.DisplayName != "" {
				text = emoji.DisplayName
			} else {
				text = "[表情]"
			}
		}
	}
	if text == "" {
		return parsedItem{}, false
	}

	sid := strings.TrimSpace(senderID)
	self := strings.TrimSpace(selfUid)
	if self == "" {
		self = strings.TrimSpace(c.CkUid)
	}
	dir := "recv"
	if self != "" && sid != "" && sid == self {
		dir = "sent"
	}
	return parsedItem{text: text, aweType: aweType, direction: dir, image: image, video: video, emoji: emoji}, true
}

// parseEmoji 从表情 content 抠出展示信息。url 优先取 url_list[0]，其次 uri。
func parseEmoji(obj map[string]any) *ImEmoji {
	e := &ImEmoji{
		DisplayName: toStr(obj["display_name"]),
		ImageType:   toStr(obj["image_type"]),
		Width:       toInt(obj["width"]),
		Height:      toInt(obj["height"]),
		StickerID:   toStr(obj["sticker_id"]),
	}
	if u, ok := obj["url"].(map[string]any); ok {
		if list := strList(u["url_list"]); len(list) > 0 {
			e.URL = list[0]
		} else if uri, _ := u["uri"].(string); uri != "" {
			e.URL = uri
		}
	}
	return e
}

// parseMessageDisplay 各类消息体的展示文案：文本 > 富文本 > 卡片标题 > 提示语。
func (c *Client) parseMessageDisplay(obj map[string]any) string {
	if t, ok := obj["text"].(string); ok && t != "" {
		return t
	}
	if content, ok := obj["content"].(string); ok {
		body := strings.TrimSpace(strings.ReplaceAll(content, "{{web_url}}", ""))
		if body != "" {
			return body
		}
	}
	if title, ok := obj["title"]; ok && toStr(title) != "" {
		var extra any
		for _, k := range []string{"open_url", "link_url", "desc"} {
			if v, ok := obj[k]; ok && v != nil {
				extra = v
				break
			}
		}
		s := "[卡片] " + toStr(title)
		if e := toStr(extra); e != "" {
			s += " | " + e
		}
		return s
	}
	for _, key := range []string{"push_detail", "desc", "hint", "msgHint"} {
		if v, ok := obj[key]; ok && toStr(v) != "" {
			return toStr(v)
		}
	}
	if sm, ok := obj["status_msg"].(map[string]any); ok {
		if mc, ok := sm["msg_content"].(map[string]any); ok {
			if tips, ok := mc["tips"]; ok && toStr(tips) != "" {
				return "[系统] " + toStr(tips)
			}
		}
	}
	if tips, ok := obj["tips"]; ok && toStr(tips) != "" {
		return "[系统] " + toStr(tips)
	}
	return ""
}

// SendResult 发送返回（对应网关 API 的 data）。
type SendResult struct {
	ClientMsgID string `json:"client_msg_id"`
	ServerMsgID string `json:"server_msg_id"`
	PrevMsgID   string `json:"prev_msg_id"`
	ConvID      string `json:"conv_id"`
	ConvShortID string `json:"conversation_short_id"`
	SelfUID     string `json:"self_uid"`
}

// SendTextResult 发 HTTP 文本消息（imapi /v1/message/send），返回 client_msg_id / server_msg_id 等。
func (c *Client) SendTextResult(conversationID, text string) (SendResult, error) {
	return c.SendTextEx(conversationID, 0, text)
}

// SendTextEx 发文本，可带会话短 ID（回复已知会话时带上更稳；0 表示不带）。
func (c *Client) SendTextEx(conversationID string, shortID uint64, text string) (SendResult, error) {
	content := jsonNoEscape(imapiTextContent{AweType: 700, Type: 0, RichTextInfos: []any{}, Text: text})
	return c.dispatchSend(conversationID, shortID, content, msgTypeText)
}

// SendImageResult 发图片（先 UploadImage 拿 ImageAsset）。走同一个 imapi 发送通道，只是 content 不同。
func (c *Client) SendImageResult(conversationID string, shortID uint64, img ImageAsset) (SendResult, error) {
	var content imapiImageContent
	content.ResourceURL.Oid = img.Oid
	content.ResourceURL.Skey = img.Skey
	content.ResourceURL.DataSize = img.DataSize
	content.ResourceURL.Md5 = img.Md5
	content.CoverHeight = img.CoverHeight
	content.CoverWidth = img.CoverWidth
	content.CheckPics = []any{}
	content.Md5 = img.Md5
	content.FromGallery = 1
	content.AweType = 2702
	return c.dispatchSend(conversationID, shortID, jsonNoEscape(content), msgTypeImage)
}

// SendText 发一条文本。
func (c *Client) SendText(conversationID, text string) error {
	_, err := c.SendTextResult(conversationID, text)
	return err
}

// -- 小工具 -----------------------------------------------------------------

func rawURLEncode(s string) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' {
			b.WriteByte(ch)
		} else {
			b.WriteByte('%')
			b.WriteByte(hexd[ch>>4])
			b.WriteByte(hexd[ch&0xf])
		}
	}
	return b.String()
}

func jsonNoEscape(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimRight(buf.String(), "\n")
}

func parseCookies(cookie string) map[string]string {
	m := map[string]string{}
	for _, part := range strings.Split(cookie, ";") {
		p := strings.TrimSpace(part)
		if p == "" || !strings.Contains(p, "=") {
			continue
		}
		i := strings.Index(p, "=")
		m[strings.TrimSpace(p[:i])] = p[i+1:]
	}
	return m
}

func uriDecode(s string) string {
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	return s
}

func strList(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

```

### `internal/engine/httpsend.go`

```go
package engine

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 电脑版(douyin_pc / imapi) 走 HTTP，body 是 application/x-protobuf（与 WS 帧同构，去掉 frontier 外壳）。
// 无公开 .proto，直接用裸 proto 编码器(proto.go)按 HAR 硬拼。所有动作共用同一外壳，只有 cmd 号 + f8 内层不同。
const (
	imapiSendURL   = "https://imapi.douyin.com/v1/message/send"
	imapiRecallURL = "https://imapi.douyin.com/v1/message/recall"
	imapiPropURL   = "https://imapi.douyin.com/v1/message/set_property"
	webSDKVersion  = "0.1.8"
	webBuildNumber = "0d50935:feat/pc-im-group"
	webSessionAID  = "339757"
	webAppName     = "douyin_pc"
	webBiz         = "douyin_im_pc"
	webAccess      = "web_sdk"
	pcUA           = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) douyinim/1.1.33 Chrome/136.0.7103.59 Electron/36.3.2 Safari/537.36"
)

// 会话类型(field100.f2)：1=单聊(私信)，2=群聊。私信/群聊发送同一端点，只有此字段与 short_id 不同。
const (
	convTypeSingle = 1
	convTypeGroup  = 2
)

// 消息类型(field100.f6)：按内容种类取值（与会话类型无关，逆自真机 HAR：私信/群聊同一套）。
const (
	msgTypeText  = 7
	msgTypeEmoji = 5
	msgTypeImage = 27
	msgTypeVideo = 30
)

// isGroupConv 群会话 id 是纯数字（如 7681236801654178341）；私信是 "0:1:小:大"。
func isGroupConv(convID string) bool {
	return isDigits(strings.TrimSpace(convID))
}

// 复用 http.Client 以复用连接（TLS 握手）。imHTTP 用于短请求，uploadHTTP 用于上传/分片。
var (
	imHTTP     = &http.Client{Timeout: 30 * time.Second}
	uploadHTTP = &http.Client{Timeout: 3 * time.Minute}
)

// imapiTextContent 文本 content JSON（字段顺序照 HAR：aweType,type,richTextInfos,text）。
type imapiTextContent struct {
	AweType       int    `json:"aweType"`
	Type          int    `json:"type"`
	RichTextInfos []any  `json:"richTextInfos"`
	Text          string `json:"text"`
}

// ImageAsset upload_image 的产物，喂给发图。
type ImageAsset struct {
	Oid         string `json:"oid"`
	Skey        string `json:"skey"`
	DataSize    int    `json:"data_size"`
	Md5         string `json:"md5"`
	CoverWidth  int    `json:"cover_width"`
	CoverHeight int    `json:"cover_height"`
}

// imapiImageContent 图片 content JSON（字段顺序照 HAR）。
type imapiImageContent struct {
	ResourceURL struct {
		Oid      string `json:"oid"`
		Skey     string `json:"skey"`
		DataSize int    `json:"data_size"`
		Md5      string `json:"md5"`
	} `json:"resource_url"`
	CoverHeight int    `json:"cover_height"`
	CoverWidth  int    `json:"cover_width"`
	CheckPics   []any  `json:"check_pics"`
	Md5         string `json:"md5"`
	FromGallery int    `json:"from_gallery"`
	AweType     int    `json:"aweType"`
}

func (c *Client) deviceID() string {
	if strings.TrimSpace(c.DeviceID) != "" {
		return c.DeviceID
	}
	return c.CkUid // 兜底
}

// fingerprintKVs f15 里的浏览器指纹 KV（session_did 用给定 device_id）。
func fingerprintKVs(dev string) [][2]string {
	return [][2]string{
		{"session_aid", webSessionAID}, {"session_did", dev}, {"app_name", webAppName},
		{"priority_region", "cn"}, {"user_agent", pcUA}, {"cookie_enabled", "true"},
		{"browser_language", "zh-CN"}, {"browser_platform", "Win32"}, {"browser_name", "Mozilla"},
		{"browser_version", strings.TrimPrefix(pcUA, "Mozilla/")}, {"browser_online", "true"},
		{"screen_width", "1707"}, {"screen_height", "1067"}, {"referer", ""},
		{"timezone_name", "Asia/Shanghai"}, {"is-retry", "0"},
	}
}

// buildEnvelope imapi 通用外壳：cmd + f8(内层 fieldNum→inner) + 指纹。所有动作共用。
func (c *Client) buildEnvelope(cmd, innerField int, inner []byte, dev string) []byte {
	body := concat(
		encodeFieldVarint(1, uint64(cmd)),
		encodeFieldVarint(2, uint64(c.nextSeq())),
		encodeLenDelimS(3, webSDKVersion),
		encodeLenDelimS(4, ""),
		encodeFieldVarint(5, 3),
		encodeFieldVarint(6, 0),
		encodeLenDelimS(7, webBuildNumber),
		encodeLenDelim(8, encodeLenDelim(innerField, inner)),
		encodeLenDelimS(9, dev),
		encodeLenDelimS(11, webAppName),
		encodeLenDelimS(14, "360000"),
	)
	for _, kv := range fingerprintKVs(dev) {
		body = append(body, encodeKvPair(15, kv[0], kv[1])...)
	}
	body = append(body, encodeFieldVarint(18, 1)...)
	body = append(body, encodeLenDelimS(21, webBiz)...)
	body = append(body, encodeLenDelimS(22, webAccess)...)
	return body
}

// buildIMAPIBody 组发消息(cmd100)的 body，返回 (body, clientMsgID)。
// convType：1 单聊 / 2 群聊；msgType：内容种类(文本7/表情5/图片27/视频30)。
func (c *Client) buildIMAPIBody(convID string, shortID uint64, contentJSON string, convType, msgType int) ([]byte, string) {
	ms := time.Now().UnixMilli()
	clientMsgID := uuid.NewString()
	field100 := concat(
		encodeLenDelimS(1, convID),
		encodeFieldVarint(2, uint64(convType)),
		encodeFieldVarint(3, shortID),
		encodeLenDelimS(4, contentJSON),
		encodeKvPair(5, "s:mentioned_users", ""),
		encodeKvPair(5, "s:client_message_id", clientMsgID),
		encodeKvPair(5, "s:stime", fmt.Sprintf("%d.%04d", ms, ms%10000)),
		encodeFieldVarint(6, uint64(msgType)),
		encodeLenDelimS(8, clientMsgID),
	)
	return c.buildEnvelope(100, 100, field100, c.deviceID()), clientMsgID
}

// postIMAPIRaw POST 一段 protobuf 到 imapi，返回响应字节。
func (c *Client) postIMAPIRaw(url string, body []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("User-Agent", pcUA)
	req.Header.Set("Cookie", c.Cookie)
	req.Header.Set("Referer", "https://imdesktop.douyin.com")
	resp, err := imHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return rb, fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet(rb))
	}
	return rb, nil
}

// resolveConvSend 由 convID 形态定发送用的 (conv_type, short_id)：
// 纯数字=群聊(short_id 即会话号)，"0:1:.."=私信(short_id 走收包缓存)。HTTP/WS 两条通道共用。
func (c *Client) resolveConvSend(convID string, shortID uint64) (int, uint64) {
	if isGroupConv(convID) {
		if shortID == 0 {
			shortID, _ = strconv.ParseUint(strings.TrimSpace(convID), 10, 64)
		}
		return convTypeGroup, shortID
	}
	return convTypeSingle, c.resolveShort(convID, shortID)
}

// dispatchSend 按 SendChannel 选发送通道：ws 走安卓 frontier WS，否则(默认)走 HTTP imapi。
// content / conv_type / msg_type 两条通道完全复用，只有传输外壳不同。
func (c *Client) dispatchSend(convID string, shortID uint64, contentJSON string, msgType int) (SendResult, error) {
	if strings.EqualFold(strings.TrimSpace(c.SendChannel), "ws") {
		return c.sendViaWS(convID, shortID, contentJSON, msgType)
	}
	return c.sendIMAPI(convID, shortID, contentJSON, msgType)
}

// sendIMAPI 发消息(cmd100)并解析回执（f3=status,0=OK；f6→f100→f1=server_msg_id）。
func (c *Client) sendIMAPI(convID string, shortID uint64, contentJSON string, msgType int) (SendResult, error) {
	convType, shortID := c.resolveConvSend(convID, shortID)
	res := SendResult{ConvID: convID, SelfUID: c.CkUid, ConvShortID: u64str(shortID)}
	if strings.TrimSpace(c.CkUid) == "" {
		return res, fmt.Errorf("未初始化：缺少 user_id")
	}
	body, clientMsgID := c.buildIMAPIBody(convID, shortID, contentJSON, convType, msgType)
	res.ClientMsgID = clientMsgID
	rb, err := c.postIMAPIRaw(imapiSendURL, body)
	if err != nil {
		return res, err
	}
	top := decodeTop(rb)
	if status, _ := searchPath(top, []int{3}); status != 0 {
		return res, fmt.Errorf("发送失败 status=%d: %s", status, snippet(rb))
	}
	if smid, ok := searchPath(top, []int{6, 100, 1}); ok {
		res.ServerMsgID = strconv.FormatUint(smid, 10)
	}
	return res, nil
}

func u64str(v uint64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatUint(v, 10)
}

func snippet(b []byte) string {
	if len(b) > 160 {
		return string(b[:160])
	}
	return string(b)
}

```

### `internal/engine/wssend.go`

```go
package engine

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// WS 发送通道：走安卓 frontier(/ws/v2) 发 cmd100 帧，绕开 HTTP imapi(douyin_pc web_sdk)群聊被风控(7523)的问题。
// 逆自 TS ImClient：buildSendMessage(ch1 douyin_main) + buildAndroidCmd100Inner + wrapAndroidCmd100Outer + drainSendAck。
// content / conv_type / msg_type 与 HTTP 通道完全复用；这里只做"安卓外壳 + 发帧 + 等回执"。
//
// 帧三层：
//
//	外层(frontier)  f1 seq f2 ts f3 5 f4 1 f5 KV{cmd100..} f6/f7 "pb" f8=inner
//	内层(cmd100)    f1 100 f2 seq f3 sdkver f7 build f8=msgWrapper f9 uid f11 "android" f15 KV.. f21/f22 biz/access
//	msgWrapper      f100 = field100{ f1 conv_id f2 conv_type f3 short f4 content f5 ext.. f6 msg_type [f7 ticket] f8 cmid f12 ext12.. }

const (
	wsSendBiz    = "douyin"
	wsSendAccess = "douyin_main"
)

// wsCh1TextContent 安卓 douyin_main(ch1) 的文本 content（字段顺序照 TS buildSendMessage case 1）。
// 与 HTTP(web_sdk)的 imapiTextContent 形状不同，走 WS 时用这套更贴近真机安卓端。
type wsCh1TextContent struct {
	Type            int    `json:"type"`
	InstructionType int    `json:"instruction_type"`
	ItemTypeLocal   int    `json:"item_type_local"`
	Text            string `json:"text"`
	CreatedAt       int    `json:"createdAt"`
	IsCard          bool   `json:"is_card"`
	MsgHint         string `json:"msgHint"`
	AweType         int    `json:"aweType"`
}

// wsAdaptContent 把上层(按 HTTP/web 形状)造好的 content 适配成 WS(安卓 ch1)形状。
// 目前仅文本换成 ch1 shape（群聊主要场景）；图片/表情/视频暂复用原 content。
func wsAdaptContent(contentJSON string, msgType int) string {
	if msgType != msgTypeText {
		return contentJSON
	}
	var m map[string]any
	if json.Unmarshal([]byte(contentJSON), &m) != nil {
		return contentJSON
	}
	// 只换"纯文本"(aweType 700 + text)；引用回复(refmsg_*)也走 msgTypeText，但结构不同，原样放行。
	if _, isReply := m["refmsg_type"]; isReply {
		return contentJSON
	}
	text, ok := m["text"].(string)
	if !ok || toInt(m["aweType"]) != 700 {
		return contentJSON
	}
	return jsonNoEscape(wsCh1TextContent{
		Type: 0, InstructionType: 0, ItemTypeLocal: -1, Text: text,
		CreatedAt: 0, IsCard: false, MsgHint: "", AweType: 700,
	})
}

// sendViaWS 通过安卓 frontier WS 发一条消息，读回执拿 server_msg_id；被风控拦截则明确报错。
func (c *Client) sendViaWS(convID string, shortID uint64, content string, msgType int) (SendResult, error) {
	convType, short := c.resolveConvSend(convID, shortID)
	res := SendResult{ConvID: convID, SelfUID: c.CkUid, ConvShortID: u64str(short)}
	if c.CkUid == "" {
		return res, fmt.Errorf("未初始化：缺少 user_id")
	}
	payload, cmid := c.buildWSSendPayload(convID, short, content, convType, msgType)
	res.ClientMsgID = cmid

	conn, err := c.makeClient(c.buildAndroidSendWsURL())
	if err != nil {
		return res, fmt.Errorf("WS 连接失败: %w", err)
	}
	defer conn.Close()
	if err := conn.Send(payload); err != nil {
		return res, fmt.Errorf("WS 发送失败: %w", err)
	}

	ack := c.drainSendAck(conn, cmid, 4*time.Second)
	if ack.serverMsgID != "" {
		res.ServerMsgID = ack.serverMsgID
	}
	if ack.blocked {
		return res, fmt.Errorf("WS 发送被拦截(未送达): %s", ack.reason)
	}
	if ack.serverMsgID == "" {
		return res, fmt.Errorf("WS 发送超时：4s 内未收到回执（可能被静默拦截或会话号不对）")
	}
	return res, nil
}

// buildWSSendPayload 组一条 WS cmd100 发送帧，返回 (帧字节, client_msg_id)。
func (c *Client) buildWSSendPayload(convID string, shortID uint64, content string, convType, msgType int) ([]byte, string) {
	seqID := c.nextSeq()
	ms := time.Now().UnixMilli()
	cmid := uuid.NewString()

	field100 := concat(
		encodeLenDelimS(1, convID),
		encodeFieldVarint(2, uint64(convType)),
		encodeFieldVarint(3, shortID),
		encodeLenDelimS(4, wsAdaptContent(content, msgType)),
	)
	for _, kv := range androidSendExt(ms) {
		field100 = append(field100, encodeKvPair(5, kv[0], kv[1])...)
	}
	field100 = append(field100, encodeFieldVarint(6, uint64(msgType))...)
	// f7 ticket 服务端下发、按会话缓存；首发为空，多数会话不需要，暂不携带。
	field100 = append(field100, encodeLenDelimS(8, cmid)...)
	for _, kv := range androidSendExt12 {
		field100 = append(field100, encodeKvPair(12, kv[0], kv[1])...)
	}

	msgWrapper := encodeLenDelim(100, field100)
	return wrapAndroidCmd100Outer(c.buildAndroidCmd100Inner(msgWrapper, seqID), seqID, ms), cmid
}

// buildAndroidCmd100Inner 安卓 IM SDK 的 cmd100 内层外壳（对应 HTTP 侧 buildEnvelope 的安卓版）。
func (c *Client) buildAndroidCmd100Inner(msgWrapper []byte, seqID int) []byte {
	dev := c.CkUid
	parts := concat(
		encodeFieldVarint(1, 100),
		encodeFieldVarint(2, uint64(seqID)),
		encodeLenDelimS(3, awemeSDKVersion),
		encodeFieldVarint(5, 1),
		encodeFieldVarint(6, 0),
		encodeLenDelimS(7, awemeBuildNumber2),
		encodeLenDelim(8, msgWrapper),
		encodeLenDelimS(9, dev),
		encodeLenDelimS(10, awemeChannel),
		encodeLenDelimS(11, "android"),
		encodeLenDelimS(12, awemeDeviceType),
		encodeLenDelimS(13, awemeOSVersion),
		encodeLenDelimS(14, awemeVersionCode),
	)
	for _, kv := range [][2]string{
		{"app_name", awemeAppName}, {"iid", dev}, {"version_code", awemeVersionCode},
		{"net_mcc_mnc", "46000"}, {"aid", awemeAID}, {"flow-tag", "new"}, {"user-agent", awemeUA},
	} {
		parts = append(parts, encodeKvPair(15, kv[0], kv[1])...)
	}
	parts = append(parts, encodeFieldVarint(18, 0)...)
	parts = append(parts, encodeLenDelimS(21, wsSendBiz)...)
	parts = append(parts, encodeLenDelimS(22, wsSendAccess)...)
	return parts
}

// wrapAndroidCmd100Outer frontier 上行外层帧。
func wrapAndroidCmd100Outer(inner []byte, seqID int, ms int64) []byte {
	out := concat(
		encodeFieldVarint(1, uint64(seqID)),
		encodeFieldVarint(2, uint64(ms)),
		encodeFieldVarint(3, 5),
		encodeFieldVarint(4, 1),
	)
	seq := strconv.Itoa(seqID)
	for _, kv := range [][2]string{
		{"msg_type", "cmd100"}, {"seq_id", seq}, {"cmd", "100"}, {"is-retry", "0"}, {"flow-tag", "new"},
	} {
		out = append(out, encodeKvPair(5, kv[0], kv[1])...)
	}
	out = append(out, encodeLenDelimS(6, "pb")...)
	out = append(out, encodeLenDelimS(7, "pb")...)
	out = append(out, encodeLenDelim(8, inner)...)
	return out
}

// androidSendExt ch1(douyin_main) 的 f5 ext KV（含时间戳，逆自 TS buildSendMessage case 1）。
func androidSendExt(ms int64) [][2]string {
	return [][2]string{
		{"s:ticket_mode", "0"},
		{"im_client_send_msg_time", strconv.FormatInt(ms-500, 10)},
		{"a:plv", "1"},
		{"a:access", wsSendAccess},
		{"s:biz_aid", awemeAID},
		{"chat_scene", "normal"},
		{"a:msg_scene", "1"},
		{"im_sdk_client_send_msg_time", strconv.FormatInt(ms-375, 10)},
		{"a:relation_type", "0:0"},
		{"a:smp_token_fetch", "11"},
		{"a:ntp_ready", "2"},
		{"s:sync_2_newdx", "1"},
		{"old_client_message_id", strconv.FormatInt(ms, 10)},
		{"s:mode", "0"},
		{"a:enter_method", "click_message"},
		{"a:biz", wsSendBiz},
		{"s:is_stranger", "false"},
		{"source_aid", awemeAID},
		{"s:saas_sdk", "false"},
		{"a:sync2dx", "1"},
		{"s:refer", "3"},
	}
}

var androidSendExt12 = [][2]string{
	{"s:reverse_creator_im_ex", "0"},
	{"a:from_role_ids", ""},
	{"s:im_creator_chat_opt_exp", "0"},
	{"s:send_ignore_ticket", "true"},
	{"s:im_chat_priv_opt_exp", "1"},
	{"a:to_role_ids", "[]"},
}

// -- 回执 -------------------------------------------------------------------

type wsAck struct {
	serverMsgID string
	blocked     bool
	reason      string
}

// drainSendAck 发完后读回执帧直到拿到本条的 ack 或超时。回执结构同收包帧：
// .8.6.500.5[*] 里 f9 KV[s:client_message_id]==本条 → f3=server_msg_id；风控看 shark/callback。
func (c *Client) drainSendAck(conn *WsConn, wantCmid string, timeout time.Duration) wsAck {
	deadline := time.Now().Add(timeout)
	var ack wsAck
	for time.Now().Before(deadline) {
		raw, err := conn.Receive(350 * time.Millisecond)
		if err != nil {
			break
		}
		if len(raw) == 0 {
			continue
		}
		if matchSendAck(decodeTop(raw), wantCmid, &ack) {
			break
		}
	}
	return ack
}

func matchSendAck(top []ProtoField, wantCmid string, ack *wsAck) bool {
	for _, f8 := range childMsgs(top, 8) {
		for _, f6 := range childMsgs(f8, 6) {
			for _, f500 := range childMsgs(f6, 500) {
				for _, msg := range childMsgs(f500, 5) {
					kv := collectKV(msg, 9)
					if kv["s:client_message_id"] != wantCmid {
						continue
					}
					if sid := firstVarint(msg, 3); sid != 0 {
						ack.serverMsgID = strconv.FormatUint(sid, 10)
					}
					if kv["s:vcd_shark_decision"] == "BLOCK" || blockedCallback(kv["im_callback_status_code"]) {
						ack.blocked = true
						if kv["s:vcd_shark_decision"] == "BLOCK" {
							ack.reason = "shark=BLOCK"
						} else {
							ack.reason = "callback=" + kv["im_callback_status_code"]
						}
					}
					return true
				}
			}
		}
	}
	return false
}

func blockedCallback(code string) bool {
	switch code {
	case "8101", "8610", "10502":
		return true
	}
	return false
}

// collectKV 收集重复 KV 字段(fieldNum){f1:key, f2:val}。
func collectKV(fields []ProtoField, fieldNum int) map[string]string {
	kv := map[string]string{}
	for _, f := range fields {
		if f.Field != fieldNum || f.Type != "message" {
			continue
		}
		var k, v string
		for _, sub := range f.VMsg {
			if sub.Field == 1 && sub.Type == "string" {
				k = sub.VStr
			}
			if sub.Field == 2 && sub.Type == "string" {
				v = sub.VStr
			}
		}
		if k != "" {
			kv[k] = v
		}
	}
	return kv
}

```

### `internal/engine/imactions.go`

```go
package engine

import (
	"fmt"
	"strconv"
	"strings"
)

// 撤回 / 表情 / 回复：共用 imapi 外壳(buildEnvelope)，只有 cmd 号与内层不同。逆自真机 HAR。

// Recall 撤回一条消息（cmd 702，f702{conv_id, short_id, 1, server_msg_id}）。
func (c *Client) Recall(convID string, shortID, serverMsgID uint64) error {
	if strings.TrimSpace(c.CkUid) == "" {
		return fmt.Errorf("未初始化：缺少 user_id")
	}
	shortID = c.resolveShort(convID, shortID)
	f702 := concat(
		encodeLenDelimS(1, convID),
		encodeFieldVarint(2, shortID),
		encodeFieldVarint(3, 1),
		encodeFieldVarint(4, serverMsgID),
	)
	body := c.buildEnvelope(702, 702, f702, "0")
	rb, err := c.postIMAPIRaw(imapiRecallURL, body)
	if err != nil {
		return err
	}
	if status, ok := searchPath(decodeTop(rb), []int{3}); ok && status != 0 {
		return fmt.Errorf("撤回失败 status=%d: %s", status, snippet(rb))
	}
	return nil
}

// -- 表情（cmd 100，aweType 507）------------------------------------------

type imapiEmojiURL struct {
	Height   int      `json:"height"`
	DataSize int      `json:"data_size"`
	URI      string   `json:"uri"`
	URLList  []string `json:"url_list"`
	Width    int      `json:"width"`
}

type imapiEmojiContent struct {
	DisplayName            string        `json:"display_name"`
	Height                 int           `json:"height"`
	Width                  int           `json:"width"`
	ImageID                int           `json:"image_id"`
	ImageType              string        `json:"image_type"`
	PackageID              int           `json:"package_id"`
	ShowNotice             bool          `json:"show_notice"`
	ResourceType           int           `json:"resource_type"`
	UpdateConversationTime bool          `json:"updateConversationTime"`
	URL                    imapiEmojiURL `json:"url"`
	CreatedAt              int           `json:"createdAt"`
	IsCard                 bool          `json:"is_card"`
	MsgHint                string        `json:"msgHint"`
	AweType                int           `json:"aweType"`
}

// EmojiSpec 发表情入参。URL 是表情图地址（可从表情库拿）。
type EmojiSpec struct {
	DisplayName   string
	URL           string
	Width, Height int
	ImageType     string // 默认 png
	PackageID     int
}

// SendEmojiResult 发一个表情。
func (c *Client) SendEmojiResult(convID string, shortID uint64, e EmojiSpec) (SendResult, error) {
	if e.Width == 0 {
		e.Width = 100
	}
	if e.Height == 0 {
		e.Height = 100
	}
	if e.ImageType == "" {
		e.ImageType = "png"
	}
	content := imapiEmojiContent{
		DisplayName: e.DisplayName, Height: e.Height, Width: e.Width,
		ImageID: 0, ImageType: e.ImageType, PackageID: e.PackageID,
		ShowNotice: false, ResourceType: 4, UpdateConversationTime: true,
		URL:       imapiEmojiURL{URI: e.URL, URLList: []string{e.URL}},
		CreatedAt: 0, IsCard: false, MsgHint: "", AweType: 507,
	}
	return c.dispatchSend(convID, shortID, jsonNoEscape(content), msgTypeEmoji)
}

// -- 回复（cmd 100，content 带 refmsg_*）-----------------------------------

type imapiReplyContent struct {
	RefmsgType    int    `json:"refmsg_type"`
	Content       string `json:"content"`
	RefmsgUID     string `json:"refmsg_uid"`
	RefmsgSecUID  string `json:"refmsg_sec_uid"`
	Nickname      string `json:"nickname"`
	RefmsgContent string `json:"refmsg_content"`
	Version       int    `json:"version"`
	ItemID        string `json:"itemId"`
	SceneType     int    `json:"scene_type"`
}

// ReplySpec 回复入参。RefText 是被回复消息的原文（用于重建 refmsg_content）。
type ReplySpec struct {
	Text              string
	RefUID, RefSecUID string
	Nickname          string
	RefText           string
}

// SendReplyResult 回复一条消息（引用原文）。
func (c *Client) SendReplyResult(convID string, shortID uint64, r ReplySpec) (SendResult, error) {
	refContent := jsonNoEscape(imapiTextContent{AweType: 700, Type: 0, RichTextInfos: []any{}, Text: r.RefText})
	content := imapiReplyContent{
		RefmsgType: 7, Content: r.Text, RefmsgUID: r.RefUID, RefmsgSecUID: r.RefSecUID,
		Nickname: r.Nickname, RefmsgContent: refContent, Version: 1, ItemID: "", SceneType: 1,
	}
	return c.dispatchSend(convID, shortID, jsonNoEscape(content), msgTypeText)
}

// ParseUint 宽松解析无符号整数（供网关拼 server_msg_id / short_id）。
func ParseUint(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return n
}

```

### `internal/engine/convlist.go`

```go
package engine

import (
	"fmt"
	"strconv"
	"strings"
)

// 会话列表(cmd 2006)：私信 + 群聊都在里面。逆自真机 HAR imapi /v1/conversation/list。
const imapiConvListURL = "https://imapi.douyin.com/v1/conversation/list"

// ConvMember 会话成员。
type ConvMember struct {
	UID    string `json:"uid"`
	SecUID string `json:"sec_uid"`
	Role   int    `json:"role"`
}

// Conversation 一条会话（群或单聊）。
type Conversation struct {
	ConvID      string       `json:"conv_id"`
	IsGroup     bool         `json:"is_group"`
	ConvType    int          `json:"conv_type"`
	ShortID     string       `json:"conv_short_id"`
	Avatar      string       `json:"avatar"`
	OwnerUID    string       `json:"owner_uid"`
	LastMsgTime int64        `json:"last_msg_time"`
	Members     []ConvMember `json:"members"`
}

// ListConversations 拉会话列表（cmd 2006）。count 拉取条数（默认 20）。
func (c *Client) ListConversations(count int) ([]Conversation, error) {
	if strings.TrimSpace(c.CkUid) == "" {
		return nil, fmt.Errorf("未初始化：缺少 user_id")
	}
	if count <= 0 {
		count = 20
	}
	// 内层参数照 HAR：f1=1 f2=0(cursor) f3=2 f4=count
	inner := concat(
		encodeFieldVarint(1, 1),
		encodeFieldVarint(2, 0),
		encodeFieldVarint(3, 2),
		encodeFieldVarint(4, uint64(count)),
	)
	body := c.buildEnvelope(2006, 2006, inner, "0") // device_id 照 HAR 为 "0"
	rb, err := c.postIMAPIRaw(imapiConvListURL, body)
	if err != nil {
		return nil, err
	}
	if status, ok := searchPath(decodeTop(rb), []int{3}); ok && status != 0 {
		return nil, fmt.Errorf("拉会话列表失败 status=%d: %s", status, snippet(rb))
	}
	return parseConvListResp(rb), nil
}

// parseConvListResp 解会话列表响应：f6 → f2006 → 重复的 f1 每个是一条会话。
func parseConvListResp(rb []byte) []Conversation {
	var out []Conversation
	for _, f6 := range childMsgs(decodeTop(rb), 6) {
		for _, box := range childMsgs(f6, 2006) {
			for _, cv := range childMsgs(box, 1) {
				out = append(out, parseConversation(cv))
			}
		}
	}
	return out
}

func parseConversation(cv []ProtoField) Conversation {
	conv := Conversation{ConvID: firstStr(cv, 1), ConvType: int(firstVarint(cv, 3))}
	conv.IsGroup = conv.ConvType == convTypeGroup
	if sid := firstVarint(cv, 2); sid != 0 {
		conv.ShortID = strconv.FormatUint(sid, 10)
	}
	// 成员 f6 → 重复 f1{uid=f1, role=f3, sec_uid=f5}
	for _, part := range childMsgs(cv, 6) {
		for _, mem := range childMsgs(part, 1) {
			uid := firstVarint(mem, 1)
			if uid == 0 {
				continue
			}
			conv.Members = append(conv.Members, ConvMember{
				UID: strconv.FormatUint(uid, 10), Role: int(firstVarint(mem, 3)), SecUID: firstStr(mem, 5),
			})
		}
	}
	// 核心信息 f50：avatar=f7, owner=f12
	if core := firstMsg(cv, 50); core != nil {
		conv.Avatar = firstStr(core, 7)
		if o := firstVarint(core, 12); o != 0 {
			conv.OwnerUID = strconv.FormatUint(o, 10)
		}
	}
	// 状态 f51：last_msg_time=f10
	if st := firstMsg(cv, 51); st != nil {
		conv.LastMsgTime = int64(firstVarint(st, 10))
	}
	return conv
}

// -- ProtoField 小工具（repeated 感知；searchPath 只取首个 varint，这里补齐）------

func childMsgs(fields []ProtoField, num int) [][]ProtoField {
	var out [][]ProtoField
	for _, f := range fields {
		if f.Field == num && f.Type == "message" {
			out = append(out, f.VMsg)
		}
	}
	return out
}

func firstMsg(fields []ProtoField, num int) []ProtoField {
	for _, f := range fields {
		if f.Field == num && f.Type == "message" {
			return f.VMsg
		}
	}
	return nil
}

func firstStr(fields []ProtoField, num int) string {
	for _, f := range fields {
		if f.Field == num && f.Type == "string" {
			return f.VStr
		}
	}
	return ""
}

func firstVarint(fields []ProtoField, num int) uint64 {
	for _, f := range fields {
		if f.Field == num && f.Type == "varint" {
			return f.VUint
		}
	}
	return 0
}

```

### `internal/engine/upload.go`

```go
package engine

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"image"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"

	"github.com/google/uuid"
)

// 图片上传：走电脑版的 TOS/VOD 上传链（标准 AWS SigV4 签名），拿到发图用的 ImageAsset。
// 逆自真机 HAR：config/v2(拿 STS 凭证) → ApplyUploadInner(SigV4) → TOS PUT → CommitUploadInner(SigV4)。
const (
	uploadConfigURL = "https://www.douyin.com/aweme/v1/web/im/upload/config/v2"
	vodBase         = "https://vod.bytedanceapi.com/"
	vodRegion       = "cn-north-1"
	vodService      = "vod"
)

type stsCreds struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	SpaceName       string
}

// UploadImage 上传图片字节，返回可直接发送的 ImageAsset。
func (c *Client) UploadImage(imageBytes []byte) (ImageAsset, error) {
	var out ImageAsset
	if len(imageBytes) == 0 {
		return out, fmt.Errorf("空图片")
	}
	creds, err := c.getUploadConfig()
	if err != nil {
		return out, fmt.Errorf("拿上传凭证失败: %w", err)
	}

	size := len(imageBytes)
	crc := fmt.Sprintf("%08x", crc32.ChecksumIEEE(imageBytes))
	w, h := 0, 0
	if cfg, _, e := image.DecodeConfig(bytes.NewReader(imageBytes)); e == nil {
		w, h = cfg.Width, cfg.Height
	}

	storeURI, auth, host, sessionKey, err := c.applyUpload(creds, creds.SpaceName, "image", size)
	if err != nil {
		return out, fmt.Errorf("ApplyUpload 失败: %w", err)
	}
	if err := c.tosPut(host, storeURI, auth, crc, imageBytes); err != nil {
		return out, fmt.Errorf("TOS 上传失败: %w", err)
	}
	oid, skey, md5s, err := c.commitUpload(creds, sessionKey)
	if err != nil {
		return out, fmt.Errorf("CommitUpload 失败: %w", err)
	}
	return ImageAsset{Oid: oid, Skey: skey, Md5: md5s, DataSize: size, CoverWidth: w, CoverHeight: h}, nil
}

// getUploadConfig GET config/v2 拿 STS 凭证 + space_name（cookie 鉴权，无 a_bogus）。
func (c *Client) getUploadConfig() (stsCreds, error) {
	var cr stsCreds
	req, _ := http.NewRequest("GET", uploadConfigURL+"?"+c.pcFingerprintQuery(), nil)
	req.Header.Set("User-Agent", pcUA)
	req.Header.Set("Cookie", c.Cookie)
	req.Header.Set("Referer", "https://www.douyin.com/")
	resp, err := imHTTP.Do(req)
	if err != nil {
		return cr, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var j struct {
		PIC struct {
			AccessKeyID     string `json:"access_key_id"`
			SecretAccessKey string `json:"secret_access_key"`
			SessionToken    string `json:"session_token"`
			SpaceName       string `json:"space_name"`
		} `json:"public_image_config"`
	}
	if err := json.Unmarshal(rb, &j); err != nil {
		return cr, fmt.Errorf("解析失败: %s", snippet(rb))
	}
	if j.PIC.AccessKeyID == "" || j.PIC.SecretAccessKey == "" {
		return cr, fmt.Errorf("无 STS 凭证（cookie 失效?）: %s", snippet(rb))
	}
	return stsCreds{j.PIC.AccessKeyID, j.PIC.SecretAccessKey, j.PIC.SessionToken, j.PIC.SpaceName}, nil
}

// applyUpload GET ApplyUploadInner（SigV4）→ storeURI, auth(JWT), uploadHost, sessionKey。
// 图片响应在 Result.UploadAddress；视频（分片）在 Result.InnerUploadAddress.UploadNodes[0]。
func (c *Client) applyUpload(cr stsCreds, space, fileType string, size int) (storeURI, auth, host, sessionKey string, err error) {
	query := map[string]string{
		"Action": "ApplyUploadInner", "Version": "2020-11-19", "SpaceName": space,
		"FileType": fileType, "IsInner": "1", "NeedFallback": "true",
		"FileSize": strconv.Itoa(size), "s": randLower(11),
	}
	req := vodSignedRequest("GET", query, nil, cr)
	resp, e := imHTTP.Do(req)
	if e != nil {
		return "", "", "", "", e
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	type storeInfo struct {
		StoreUri string `json:"StoreUri"`
		Auth     string `json:"Auth"`
	}
	var j struct {
		Result struct {
			UploadAddress *struct {
				StoreInfos  []storeInfo `json:"StoreInfos"`
				UploadHosts []string    `json:"UploadHosts"`
				SessionKey  string      `json:"SessionKey"`
			} `json:"UploadAddress"`
			InnerUploadAddress *struct {
				UploadNodes []struct {
					StoreInfos []storeInfo `json:"StoreInfos"`
					UploadHost string      `json:"UploadHost"`
					SessionKey string      `json:"SessionKey"`
				} `json:"UploadNodes"`
			} `json:"InnerUploadAddress"`
		} `json:"Result"`
	}
	if json.Unmarshal(rb, &j) != nil {
		return "", "", "", "", fmt.Errorf("响应异常: %s", snippet(rb))
	}
	if ua := j.Result.UploadAddress; ua != nil && len(ua.StoreInfos) > 0 && len(ua.UploadHosts) > 0 {
		return ua.StoreInfos[0].StoreUri, ua.StoreInfos[0].Auth, ua.UploadHosts[0], ua.SessionKey, nil
	}
	if iu := j.Result.InnerUploadAddress; iu != nil && len(iu.UploadNodes) > 0 && len(iu.UploadNodes[0].StoreInfos) > 0 {
		n := iu.UploadNodes[0]
		return n.StoreInfos[0].StoreUri, n.StoreInfos[0].Auth, n.UploadHost, n.SessionKey, nil
	}
	return "", "", "", "", fmt.Errorf("无上传地址: %s", snippet(rb))
}

// tosPut 把图片字节 PUT/POST 到 TOS。
func (c *Client) tosPut(host, storeURI, auth, crc string, data []byte) error {
	url := "https://" + host + "/upload/v1/" + storeURI
	req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-CRC32", crc)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Storage-U", c.CkUid)
	req.Header.Set("User-Agent", pcUA)
	resp, err := uploadHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var j struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(rb, &j) != nil || j.Code != 2000 {
		return fmt.Errorf("TOS 返回 %s", snippet(rb))
	}
	return nil
}

// commitUpload POST CommitUploadInner（SigV4）→ oid(Encryption.Uri), skey, md5。
func (c *Client) commitUpload(cr stsCreds, sessionKey string) (oid, skey, md5s string, err error) {
	query := map[string]string{"Action": "CommitUploadInner", "Version": "2020-11-19", "SpaceName": cr.SpaceName}
	body, _ := json.Marshal(map[string]string{"SessionKey": sessionKey})
	req := vodSignedRequest("POST", query, body, cr)
	req.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	resp, e := imHTTP.Do(req)
	if e != nil {
		return "", "", "", e
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var j struct {
		Result struct {
			Results []struct {
				Encryption struct {
					Uri       string `json:"Uri"`
					SecretKey string `json:"SecretKey"`
					SourceMd5 string `json:"SourceMd5"`
				} `json:"Encryption"`
			} `json:"Results"`
		} `json:"Result"`
	}
	if json.Unmarshal(rb, &j) != nil || len(j.Result.Results) == 0 {
		return "", "", "", fmt.Errorf("响应异常: %s", snippet(rb))
	}
	en := j.Result.Results[0].Encryption
	if en.Uri == "" || en.SecretKey == "" {
		return "", "", "", fmt.Errorf("无加密信息: %s", snippet(rb))
	}
	return en.Uri, en.SecretKey, en.SourceMd5, nil
}

// -- AWS SigV4 --------------------------------------------------------------

// vodSignedRequest 构造一个 SigV4 已签名的 vod 请求（body 为 nil 表示 GET/空体）。
func vodSignedRequest(method string, query map[string]string, body []byte, cr stsCreds) *http.Request {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	cq := canonicalQuery(query)
	auth, signed := vodSign(method, cq, body, cr, amzDate, dateStamp)

	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, vodBase+"?"+cq, rd)
	req.Header.Set("Authorization", auth)
	for k, v := range signed {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", pcUA)
	return req
}

// vodSign 纯计算：返回 Authorization 头 + 需随请求发送的签名头（可注入时间戳，便于对拍）。
func vodSign(method, canonicalQ string, body []byte, cr stsCreds, amzDate, dateStamp string) (string, map[string]string) {
	payloadHash := sha256Hex(body)
	signed := map[string]string{
		"x-amz-date":           amzDate,
		"x-amz-security-token": cr.SessionToken,
	}
	if method == "POST" {
		signed["x-amz-content-sha256"] = payloadHash
	}
	hk := make([]string, 0, len(signed))
	for k := range signed {
		hk = append(hk, k)
	}
	sort.Strings(hk)
	var ch strings.Builder
	for _, k := range hk {
		ch.WriteString(k + ":" + signed[k] + "\n")
	}
	signedHeaders := strings.Join(hk, ";")

	canonicalReq := method + "\n/\n" + canonicalQ + "\n" + ch.String() + "\n" + signedHeaders + "\n" + payloadHash
	scope := dateStamp + "/" + vodRegion + "/" + vodService + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonicalReq))

	key := hmacSum([]byte("AWS4"+cr.SecretAccessKey), dateStamp)
	key = hmacSum(key, vodRegion)
	key = hmacSum(key, vodService)
	key = hmacSum(key, "aws4_request")
	sig := hex.EncodeToString(hmacRaw(key, stringToSign))

	auth := "AWS4-HMAC-SHA256 Credential=" + cr.AccessKeyID + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + sig
	return auth, signed
}

// canonicalQuery 键排序后 RFC3986 编码拼接（AWS 规则）。
func canonicalQuery(q map[string]string) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = rawURLEncode(k) + "=" + rawURLEncode(q[k])
	}
	return strings.Join(parts, "&")
}

func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func hmacRaw(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
func hmacSum(key []byte, data string) []byte { return hmacRaw(key, data) }

// randLower n 位小写字母数字（cache-buster 用）。
func randLower(n int) string {
	const al = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	src := uuid.NewString() + uuid.NewString()
	for i := 0; i < n; i++ {
		b[i] = al[int(src[i])%len(al)]
	}
	return string(b)
}

```

### `internal/engine/video.go`

```go
package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"strings"
)

// 发视频：封面走图片上传(UploadImage)拿 poster，视频走 TOS 分片上传(init→transfer→finish→commit)拿 video，
// 再选传一张审核图(check_pics, maya_review 空间)。content 逆自真机 HAR。
const videoPartSize = 5 * 1024 * 1024 // 5MB / 分片

type imapiVideoContent struct {
	Video struct {
		Tkey string `json:"tkey"`
		Md5  string `json:"md5"`
		Skey string `json:"skey"`
	} `json:"video"`
	Poster struct {
		Oid  string `json:"oid"`
		Md5  string `json:"md5"`
		Skey string `json:"skey"`
	} `json:"poster"`
	Height    int      `json:"height"`
	Width     int      `json:"width"`
	CheckPics []string `json:"check_pics"`
}

// SendVideoResult 发视频。cover 是封面图字节（必填，用作 poster + 审核图）。width/height 传 0 则用封面尺寸兜底。
func (c *Client) SendVideoResult(convID string, shortID uint64, videoBytes, coverBytes []byte, width, height int) (SendResult, error) {
	var res SendResult
	if len(videoBytes) == 0 {
		return res, fmt.Errorf("空视频")
	}
	if len(coverBytes) == 0 {
		return res, fmt.Errorf("需要封面图 cover")
	}
	if strings.TrimSpace(c.CkUid) == "" {
		return res, fmt.Errorf("未初始化：缺少 user_id")
	}
	creds, err := c.getUploadConfig()
	if err != nil {
		return res, fmt.Errorf("拿上传凭证失败: %w", err)
	}
	poster, err := c.UploadImage(coverBytes)
	if err != nil {
		return res, fmt.Errorf("封面上传失败: %w", err)
	}
	tkey, vskey, vmd5, err := c.uploadVideo(creds, videoBytes)
	if err != nil {
		return res, fmt.Errorf("视频上传失败: %w", err)
	}
	checkPic := c.uploadCheckPic(creds, coverBytes) // best-effort

	if width == 0 {
		width = poster.CoverWidth
	}
	if height == 0 {
		height = poster.CoverHeight
	}
	var content imapiVideoContent
	content.Video.Tkey, content.Video.Md5, content.Video.Skey = tkey, vmd5, vskey
	content.Poster.Oid, content.Poster.Md5, content.Poster.Skey = poster.Oid, poster.Md5, poster.Skey
	content.Height, content.Width = height, width
	content.CheckPics = []string{}
	if checkPic != "" {
		content.CheckPics = []string{checkPic}
	}
	return c.dispatchSend(convID, shortID, jsonNoEscape(content), msgTypeVideo)
}

// uploadVideo TOS 分片上传视频，返回 tkey/skey/md5。
func (c *Client) uploadVideo(cr stsCreds, data []byte) (tkey, skey, md5s string, err error) {
	size := len(data)
	storeURI, auth, host, sessionKey, err := c.applyUpload(cr, cr.SpaceName, "video", size)
	if err != nil {
		return "", "", "", err
	}
	uploadID, err := c.chunkInit(host, storeURI, auth)
	if err != nil {
		return "", "", "", err
	}
	var parts []string
	n := 0
	for off := 0; off < size; off += videoPartSize {
		end := off + videoPartSize
		if end > size {
			end = size
		}
		n++
		crc := fmt.Sprintf("%08x", crc32.ChecksumIEEE(data[off:end]))
		if err = c.chunkTransfer(host, storeURI, auth, uploadID, n, crc, data[off:end]); err != nil {
			return "", "", "", err
		}
		parts = append(parts, fmt.Sprintf("%d:%s", n, crc))
	}
	if err = c.chunkFinish(host, storeURI, auth, uploadID, strings.Join(parts, ",")); err != nil {
		return "", "", "", err
	}
	return c.commitUpload(cr, sessionKey) // Encryption.Uri/SecretKey/SourceMd5
}

// chunkInit phase=init，返回 uploadid。
func (c *Client) chunkInit(host, storeURI, auth string) (string, error) {
	boundary := "----WebKitFormBoundary" + randLower(16)
	body := []byte("--" + boundary + "--\r\n")
	req, _ := http.NewRequest("POST", "https://"+host+"/upload/v1/"+storeURI+"?phase=init", bytes.NewReader(body))
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	req.Header.Set("X-Storage-U", c.CkUid)
	req.Header.Set("User-Agent", pcUA)
	resp, err := imHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var j struct {
		Code int `json:"code"`
		Data struct {
			UploadID string `json:"uploadid"`
		} `json:"data"`
	}
	rb, _ := io.ReadAll(resp.Body)
	if json.Unmarshal(rb, &j) != nil || j.Code != 2000 || j.Data.UploadID == "" {
		return "", fmt.Errorf("init 失败: %s", snippet(rb))
	}
	return j.Data.UploadID, nil
}

// chunkTransfer phase=transfer 上传一片。
func (c *Client) chunkTransfer(host, storeURI, auth, uploadID string, partNum int, crc string, part []byte) error {
	url := fmt.Sprintf("https://%s/upload/v1/%s?uploadid=%s&part_number=%d&phase=transfer", host, storeURI, uploadID, partNum)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(part))
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-CRC32", crc)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Disposition", `attachment; filename="undefined"`)
	req.Header.Set("X-Storage-U", c.CkUid)
	req.Header.Set("User-Agent", pcUA)
	resp, err := uploadHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(rb, []byte(`"code":2000`)) {
		return fmt.Errorf("part %d 失败: %s", partNum, snippet(rb))
	}
	return nil
}

// chunkFinish phase=finish，body 为 "1:crc,2:crc,..."。
func (c *Client) chunkFinish(host, storeURI, auth, uploadID, partList string) error {
	url := fmt.Sprintf("https://%s/upload/v1/%s?phase=finish&uploadid=%s", host, storeURI, uploadID)
	req, _ := http.NewRequest("POST", url, strings.NewReader(partList))
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	req.Header.Set("X-Storage-U", c.CkUid)
	req.Header.Set("User-Agent", pcUA)
	resp, err := imHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(rb, []byte(`"code":2000`)) {
		return fmt.Errorf("finish 失败: %s", snippet(rb))
	}
	return nil
}

// uploadCheckPic 把封面传到 maya_review 空间作审核图，返回 StoreUri（失败返回 ""，不阻断发送）。
func (c *Client) uploadCheckPic(cr stsCreds, cover []byte) string {
	storeURI, auth, host, _, err := c.applyUpload(cr, "maya_review", "image", len(cover))
	if err != nil {
		return ""
	}
	crc := fmt.Sprintf("%08x", crc32.ChecksumIEEE(cover))
	if c.tosPut(host, storeURI, auth, crc, cover) != nil {
		return ""
	}
	return storeURI
}

```

### `internal/engine/videoplay.go`

```go
package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

const batchPlayInfoURL = "https://imdesktop.douyin.com/maya/story/batch_play_info/v1/"

// pcFingerprintQuery 电脑版 web 接口通用的设备指纹 query（config/v2、batch_play_info 共用，无 a_bogus）。
func (c *Client) pcFingerprintQuery() string {
	dev := c.deviceID()
	q := [][2]string{
		{"aid", "339757"}, {"version_name", "1.1.33"}, {"version_code", "1.1.33"},
		{"device_platform", "win32"}, {"os_version", "10.0.26200"},
		{"screen_width", "1707"}, {"screen_height", "1067"},
		{"browser_language", "zh-CN"}, {"browser_platform", "Win32"}, {"browser_name", "Mozilla"},
		{"browser_version", strings.TrimPrefix(pcUA, "Mozilla/")}, {"browser_online", "true"}, {"cookie_enabled", "true"},
		{"device_id", dev}, {"did", dev}, {"iid", "0"},
		{"awemeim_guid", strings.ReplaceAll(uuid.NewString(), "-", "")}, {"channel", "0"},
	}
	var sb strings.Builder
	for i, kv := range q {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(kv[0] + "=" + rawURLEncode(kv[1]))
	}
	return sb.String()
}

// VideoURL 视频可播地址（batch_play_info 解出）。视频流本身仍是加密的（key=消息里的 video.skey）。
type VideoURL struct {
	MainURL    string `json:"main_url"`
	BackupURL  string `json:"backup_url"`
	ExpireTime int64  `json:"expire_time"`
}

// ResolveVideoURL 用视频 tkey 走 batch_play_info 换可播 URL（main/backup）。
func (c *Client) ResolveVideoURL(tkey string) (VideoURL, error) {
	var out VideoURL
	if strings.TrimSpace(tkey) == "" {
		return out, fmt.Errorf("空 tkey")
	}
	body, _ := json.Marshal(map[string]any{
		"req_infos":    []map[string]any{{"tos_key": tkey, "type": 2}},
		"with_caption": true,
	})
	req, _ := http.NewRequest("POST", batchPlayInfoURL+"?"+c.pcFingerprintQuery(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", pcUA)
	req.Header.Set("Cookie", c.Cookie)
	req.Header.Set("Referer", "https://imdesktop.douyin.com")
	resp, err := imHTTP.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var j struct {
		Data struct {
			PlayInfos []struct {
				EncryptedURL VideoURL `json:"encrypted_url"`
			} `json:"play_infos"`
		} `json:"data"`
	}
	if json.Unmarshal(rb, &j) != nil || len(j.Data.PlayInfos) == 0 {
		return out, fmt.Errorf("解析失败: %s", snippet(rb))
	}
	e := j.Data.PlayInfos[0].EncryptedURL
	if e.MainURL == "" {
		return out, fmt.Errorf("无播放地址: %s", snippet(rb))
	}
	return e, nil
}

```


## I. 媒体解密 (internal/media)

### `internal/media/image.go`

```go
// Package media IM 图片解码（1:1 逆自电脑版 player JS）。
// 图片下载回来是加密容器：iv(12) ‖ 密文 ‖ GCM_tag(16)，key = skey(64hex→32字节)，AES-256-GCM。
package media

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
)

// ImageResource 对应消息里的 resource_url。
type ImageResource struct {
	Skey          string   `json:"skey"`
	OriginURLList []string `json:"origin_url_list"`
	LargeURLList  []string `json:"large_url_list"`
	MediumURLList []string `json:"medium_url_list"`
	ThumbURLList  []string `json:"thumb_url_list"`
	MD5           string   `json:"md5"`
}

// DecryptImage 解密图片容器。
func DecryptImage(encrypted []byte, skeyHex string) ([]byte, error) {
	key, err := hex.DecodeString(skeyHex)
	if err != nil || len(key) != 32 {
		return nil, errors.New("skey 必须是 32 字节（64 位 hex）")
	}
	if len(encrypted) < 12+16 {
		return nil, errors.New("密文过短")
	}
	iv := encrypted[:12]
	rest := encrypted[12:] // 密文 + tag（Go GCM 约定 tag 附在末尾，与 WebCrypto 一致）
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, rest, nil)
}

// PickURL 挑一个可用图片 url（原图优先）。
func (r *ImageResource) PickURL() string {
	for _, l := range [][]string{r.OriginURLList, r.LargeURLList, r.MediumURLList, r.ThumbURLList} {
		if len(l) > 0 && l[0] != "" {
			return l[0]
		}
	}
	return ""
}

// SniffExt 从解出的字节推断扩展名。
func SniffExt(b []byte) string {
	switch {
	case len(b) >= 12 && string(b[8:12]) == "WEBP":
		return "webp"
	case len(b) >= 2 && b[0] == 0xff && b[1] == 0xd8:
		return "jpg"
	case len(b) >= 4 && b[0] == 0x89 && string(b[1:4]) == "PNG":
		return "png"
	case len(b) >= 8 && string(b[4:8]) == "ftyp":
		return "heic"
	default:
		return "img"
	}
}

func sniffMime(b []byte) string {
	switch SniffExt(b) {
	case "webp":
		return "image/webp"
	case "jpg":
		return "image/jpeg"
	case "png":
		return "image/png"
	case "heic":
		return "image/heic"
	default:
		return "application/octet-stream"
	}
}

// FetchAndDecrypt 下载 url、用 skey 解密，返回图片字节。
func FetchAndDecrypt(url, skey string) ([]byte, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Referer", "https://www.douyin.com")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	enc, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return DecryptImage(enc, skey)
}

```

### `internal/media/cenc.go`

```go
package media

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// CENC (cenc-aes-ctr) 视频解密核心，逆自电脑版 player.js 的 decoderAESCTRData。
//
// 每个 sample：把所有 protected 子样本段拼成一条，用 key + counter(IV) 走单条 AES-128-CTR 解密，
// 再按 {clear, protected} 的顺序拼回。counter 在整条 protected 流上连续递增（跨子样本不重置）。
// key = video.skey 的原始字节（AES-128 → 16 字节）；iv = senc 的 InitializationVector（8 或 16 字节，补零到 16）。

// Subsample 一个子样本的明文/密文字节数（CENC senc 里的 BytesOfClearData / BytesOfProtectedData）。
type Subsample struct {
	Clear     int
	Protected int
}

// cencDecryptSample 解一个 sample。subs 为空表示整 sample 加密。返回同长度的明文。
func cencDecryptSample(key, iv, data []byte, subs []Subsample) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	counter := make([]byte, 16)
	copy(counter, iv) // 8 字节 IV → 高位，低 8 字节为 0；16 字节 IV → 直接用
	ctr := cipher.NewCTR(block, counter)

	// 无子样本：整段都是 protected
	if len(subs) == 0 {
		out := make([]byte, len(data))
		ctr.XORKeyStream(out, data)
		return out, nil
	}

	// 拼 protected → 单条 CTR 解 → 拼回
	var protected []byte
	pos := 0
	for _, s := range subs {
		start := pos + s.Clear
		end := start + s.Protected
		if end > len(data) {
			return nil, fmt.Errorf("子样本越界: end=%d len=%d", end, len(data))
		}
		protected = append(protected, data[start:end]...)
		pos = end
	}
	dec := make([]byte, len(protected))
	ctr.XORKeyStream(dec, protected)

	out := make([]byte, 0, len(data))
	pos, dpos := 0, 0
	for _, s := range subs {
		out = append(out, data[pos:pos+s.Clear]...)      // 明文段原样
		out = append(out, dec[dpos:dpos+s.Protected]...) // 解密后的段
		pos += s.Clear + s.Protected
		dpos += s.Protected
	}
	if pos < len(data) { // 子样本没覆盖到的尾部（一般不会有）
		out = append(out, data[pos:]...)
	}
	return out, nil
}

```

### `internal/media/mp4cenc.go`

```go
package media

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// CENC MP4 解密：定位每个 sample、AES-128-CTR 解密其 protected 段、再把加密盒子改名让文件"变明文"可播。
// 结构逆自真机 payload.mp4：非分片 MP4，senc/saiz/saio 在 stbl，tenc/frma 在 stsd/encv|enca/sinf。

type mp4box struct {
	typ       string
	start     int // 盒子起始（含 header）
	dataStart int // 内容起始（header 之后）
	size      int // 盒子总长
}

func u16(b []byte, p int) int { return int(binary.BigEndian.Uint16(b[p : p+2])) }
func u32(b []byte, p int) int { return int(binary.BigEndian.Uint32(b[p : p+4])) }
func u64(b []byte, p int) int { return int(binary.BigEndian.Uint64(b[p : p+8])) }

// boxesIn 解析 [start,end) 里的同层盒子。
func boxesIn(buf []byte, start, end int) []mp4box {
	var out []mp4box
	p := start
	for p+8 <= end {
		size := u32(buf, p)
		typ := string(buf[p+4 : p+8])
		hdr := 8
		if size == 1 {
			if p+16 > end {
				break
			}
			size = u64(buf, p+8)
			hdr = 16
		} else if size == 0 {
			size = end - p
		}
		if size < hdr || p+size > end {
			break
		}
		out = append(out, mp4box{typ, p, p + hdr, size})
		p += size
	}
	return out
}

func findBox(bs []mp4box, typ string) (mp4box, bool) {
	for _, b := range bs {
		if b.typ == typ {
			return b, true
		}
	}
	return mp4box{}, false
}

func (b mp4box) children(buf []byte) []mp4box { return boxesIn(buf, b.dataStart, b.start+b.size) }
func (b mp4box) end() int                     { return b.start + b.size }

// DecryptVideo 解密整段 CENC 视频，返回可播 MP4（原地改一份拷贝，长度不变）。
func DecryptVideo(mp4 []byte, skeyHex string) ([]byte, error) {
	key, err := hex.DecodeString(skeyHex)
	if err != nil || len(key) != 16 {
		return nil, fmt.Errorf("skey 应为 16 字节(32 hex): %q", skeyHex)
	}
	buf := make([]byte, len(mp4))
	copy(buf, mp4)

	top := boxesIn(buf, 0, len(buf))
	moov, ok := findBox(top, "moov")
	if !ok {
		return nil, fmt.Errorf("无 moov")
	}
	done := 0
	for _, trak := range trakList(buf, moov) {
		if err := decryptTrak(buf, trak, key); err != nil {
			if err == errNotEncrypted {
				continue
			}
			return nil, err
		}
		done++
	}
	if done == 0 {
		return nil, fmt.Errorf("没有可解密的加密轨（可能未加密或结构不符）")
	}
	return buf, nil
}

func trakList(buf []byte, moov mp4box) []mp4box {
	var out []mp4box
	for _, c := range moov.children(buf) {
		if c.typ == "trak" {
			out = append(out, c)
		}
	}
	return out
}

var errNotEncrypted = fmt.Errorf("未加密轨")

func decryptTrak(buf []byte, trak mp4box, key []byte) error {
	mdia, ok := findBox(trak.children(buf), "mdia")
	if !ok {
		return errNotEncrypted
	}
	minf, ok := findBox(mdia.children(buf), "minf")
	if !ok {
		return errNotEncrypted
	}
	stbl, ok := findBox(minf.children(buf), "stbl")
	if !ok {
		return errNotEncrypted
	}
	sc := stbl.children(buf)
	stsd, ok := findBox(sc, "stsd")
	if !ok {
		return errNotEncrypted
	}
	// stsd 内容前 8 字节是 version+flags+entry_count，之后是 sample entry
	entries := boxesIn(buf, stsd.dataStart+8, stsd.end())
	if len(entries) == 0 {
		return errNotEncrypted
	}
	entry := entries[0]
	var visualHdr int
	switch entry.typ {
	case "encv":
		visualHdr = 78
	case "enca":
		visualHdr = 28
	default:
		return errNotEncrypted // 不是加密 sample entry
	}
	sinf, ok := findBox(boxesIn(buf, entry.dataStart+visualHdr, entry.end()), "sinf")
	if !ok {
		return errNotEncrypted
	}
	frma, ok := findBox(sinf.children(buf), "frma")
	if !ok {
		return fmt.Errorf("无 frma")
	}
	dataFormat := string(buf[frma.dataStart : frma.dataStart+4])
	schi, ok := findBox(sinf.children(buf), "schi")
	if !ok {
		return fmt.Errorf("无 schi")
	}
	tenc, ok := findBox(schi.children(buf), "tenc")
	if !ok {
		return fmt.Errorf("无 tenc")
	}
	ivSize := int(buf[tenc.dataStart+7]) // default_Per_Sample_IV_Size

	senc, ok := findBox(sc, "senc")
	if !ok {
		return errNotEncrypted // 无 senc = 无逐样本 IV
	}
	stsz, ok := findBox(sc, "stsz")
	if !ok {
		return fmt.Errorf("无 stsz")
	}
	stsc, ok := findBox(sc, "stsc")
	if !ok {
		return fmt.Errorf("无 stsc")
	}
	chunkOffsets, err := parseChunkOffsets(buf, sc)
	if err != nil {
		return err
	}

	sizes := parseStsz(buf, stsz)
	offsets := computeSampleOffsets(sizes, parseStsc(buf, stsc), chunkOffsets)
	samples := parseSenc(buf, senc, ivSize)
	if len(samples) != len(sizes) {
		return fmt.Errorf("senc(%d) 与 stsz(%d) 样本数不一致", len(samples), len(sizes))
	}

	for i := range sizes {
		off, sz := offsets[i], sizes[i]
		if off <= 0 || off+sz > len(buf) {
			return fmt.Errorf("样本 %d 越界: off=%d sz=%d", i, off, sz)
		}
		dec, err := cencDecryptSample(key, samples[i].iv, buf[off:off+sz], samples[i].subs)
		if err != nil {
			return err
		}
		copy(buf[off:off+sz], dec)
	}

	// 拆封：改名 fourcc（长度不变，偏移不动）→ 文件"变明文"
	copy(buf[entry.start+4:entry.start+8], []byte(dataFormat)) // encv→hvc1 / enca→mp4a
	renameBox(buf, sinf, "free")
	renameBox(buf, senc, "free")
	if b, ok := findBox(sc, "saiz"); ok {
		renameBox(buf, b, "free")
	}
	if b, ok := findBox(sc, "saio"); ok {
		renameBox(buf, b, "free")
	}
	return nil
}

func renameBox(buf []byte, b mp4box, typ string) { copy(buf[b.start+4:b.start+8], []byte(typ)) }

func parseStsz(buf []byte, b mp4box) []int {
	p := b.dataStart
	sampleSize := u32(buf, p+4)
	count := u32(buf, p+8)
	sizes := make([]int, count)
	if sampleSize != 0 {
		for i := range sizes {
			sizes[i] = sampleSize
		}
		return sizes
	}
	q := p + 12
	for i := 0; i < count; i++ {
		sizes[i] = u32(buf, q)
		q += 4
	}
	return sizes
}

func parseChunkOffsets(buf []byte, sc []mp4box) ([]int, error) {
	if b, ok := findBox(sc, "stco"); ok {
		count := u32(buf, b.dataStart+4)
		out := make([]int, count)
		q := b.dataStart + 8
		for i := 0; i < count; i++ {
			out[i] = u32(buf, q)
			q += 4
		}
		return out, nil
	}
	if b, ok := findBox(sc, "co64"); ok {
		count := u32(buf, b.dataStart+4)
		out := make([]int, count)
		q := b.dataStart + 8
		for i := 0; i < count; i++ {
			out[i] = u64(buf, q)
			q += 8
		}
		return out, nil
	}
	return nil, fmt.Errorf("无 stco/co64")
}

type stscEntry struct{ firstChunk, samplesPerChunk int }

func parseStsc(buf []byte, b mp4box) []stscEntry {
	count := u32(buf, b.dataStart+4)
	out := make([]stscEntry, count)
	q := b.dataStart + 8
	for i := 0; i < count; i++ {
		out[i] = stscEntry{u32(buf, q), u32(buf, q+4)}
		q += 12
	}
	return out
}

// computeSampleOffsets 按 stsc/stco/stsz 算每个 sample 的绝对文件偏移。
func computeSampleOffsets(sizes []int, stsc []stscEntry, chunkOffsets []int) []int {
	offs := make([]int, len(sizes))
	si := 0
	for ci := 0; ci < len(chunkOffsets) && si < len(sizes); ci++ {
		spc := samplesInChunk(stsc, ci+1) // 1-indexed
		off := chunkOffsets[ci]
		for s := 0; s < spc && si < len(sizes); s++ {
			offs[si] = off
			off += sizes[si]
			si++
		}
	}
	return offs
}

func samplesInChunk(stsc []stscEntry, chunk1 int) int {
	spc := 0
	for _, e := range stsc {
		if e.firstChunk <= chunk1 {
			spc = e.samplesPerChunk
		} else {
			break
		}
	}
	return spc
}

type sencSample struct {
	iv   []byte
	subs []Subsample
}

func parseSenc(buf []byte, b mp4box, ivSize int) []sencSample {
	p := b.dataStart
	flags := u32(buf, p) & 0xffffff
	count := u32(buf, p+4)
	p += 8
	out := make([]sencSample, count)
	for i := 0; i < count; i++ {
		iv := make([]byte, ivSize)
		copy(iv, buf[p:p+ivSize])
		p += ivSize
		var subs []Subsample
		if flags&2 != 0 {
			n := u16(buf, p)
			p += 2
			subs = make([]Subsample, n)
			for j := 0; j < n; j++ {
				subs[j] = Subsample{Clear: u16(buf, p), Protected: u32(buf, p+2)}
				p += 6
			}
		}
		out[i] = sencSample{iv, subs}
	}
	return out
}

```

### `internal/media/imageserver.go`

```go
package media

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// 图片解密代理：不自己监听端口，挂到网关的 HTTP mux 上共用同一端口。
//
//	GET /img?u=<encodedUrl>&k=<skey> → 下载 + AES-256-GCM 解密 → 正常图片

var (
	proxyBase string // 网关地址，如 http://127.0.0.1:9503
	proxyMu   sync.RWMutex
)

// 只允许解密图床域名，堵住"取任意 URL"的 SSRF。
var allowedImageHosts = []string{
	"douyinpic.com", "douyin.com", "iesdouyin.com", "amemv.com",
	"byteimg.com", "ibyteimg.com", "bytedance.com", "pstatp.com",
}

func allowedImageHost(rawURL string) bool {
	pu, err := url.Parse(rawURL)
	if err != nil || (pu.Scheme != "https" && pu.Scheme != "http") {
		return false
	}
	host := pu.Hostname()
	for _, s := range allowedImageHosts {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// SetProxyBase 网关启动时告知自己的地址，图片链接据此拼。
func SetProxyBase(base string) {
	proxyMu.Lock()
	proxyBase = strings.TrimRight(base, "/")
	proxyMu.Unlock()
}

// ImageHandler /img 处理器，挂到网关 mux 上。免鉴权（<img> 带不了 header）+ 域名白名单兜底。
func ImageHandler(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("u")
	k := r.URL.Query().Get("k")
	if u == "" || k == "" {
		http.Error(w, "need u & k", http.StatusBadRequest)
		return
	}
	if !allowedImageHost(u) {
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}
	data, err := FetchAndDecrypt(u, k)
	if err != nil {
		http.Error(w, "err: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", sniffMime(data))
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(data)
}

// ImageLink 拼本地解密代理链接；未设 base（网关没起）时返回原始 url。
func ImageLink(rawURL, skey string) string {
	proxyMu.RLock()
	base := proxyBase
	proxyMu.RUnlock()
	if base == "" {
		return rawURL
	}
	return base + "/img?u=" + url.QueryEscape(rawURL) + "&k=" + url.QueryEscape(skey)
}

```

### `internal/media/videoserver.go`

```go
package media

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// 视频解密：CENC 视频流本身仍是密文，key = 消息里的 video.skey。
// 播放链接走网关 /video 代理：tkey 换下载地址 → 下载 → DecryptVideo → 出明文 MP4。
// 下载地址由服务端用 tkey 换得（非调用方给的任意 URL），故无 SSRF 面；仅校验 https。

const maxVideoBytes = 512 << 20 // 512MB 兜底，IM 短视频远小于此

var videoHTTP = &http.Client{Timeout: 90 * time.Second}

// FetchVideoAndDecrypt 下载 CENC MP4（main 失败回退 backup）并用 skey 解密成可播 MP4。
func FetchVideoAndDecrypt(mainURL, backupURL, skey string) ([]byte, error) {
	enc, err := fetchVideo(mainURL)
	if err != nil && backupURL != "" {
		enc, err = fetchVideo(backupURL)
	}
	if err != nil {
		return nil, err
	}
	return DecryptVideo(enc, skey)
}

func fetchVideo(rawURL string) ([]byte, error) {
	pu, err := url.Parse(rawURL)
	if err != nil || pu.Scheme != "https" {
		return nil, fmt.Errorf("非法视频地址")
	}
	req, _ := http.NewRequest("GET", rawURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Referer", "https://www.douyin.com")
	res, err := videoHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("下载视频 HTTP %d", res.StatusCode)
	}
	return io.ReadAll(io.LimitReader(res.Body, maxVideoBytes))
}

// VideoLink 拼本地视频解密代理链接；未设 base（网关没起）时返回空串。
func VideoLink(tkey, skey string) string {
	proxyMu.RLock()
	base := proxyBase
	proxyMu.RUnlock()
	if base == "" || tkey == "" || skey == "" {
		return ""
	}
	return base + "/video?tkey=" + url.QueryEscape(tkey) + "&skey=" + url.QueryEscape(skey)
}

```


## J. 昵称解析与缓存 (internal/webapi, internal/store)

### `internal/webapi/im.go`

```go
// Package webapi 电脑版 web IM 辅助接口（a_bogus+msToken+cookie 签名）。
package webapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gobot/internal/abogus"
	"gobot/internal/sign"
	"gobot/internal/store"
)

var webHTTP = &http.Client{Timeout: 15 * time.Second}

const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) douyinim/1.1.31 Chrome/130.0.6723.58 Electron/33.4.11 Safari/537.36"

// User 解析出的用户。
type User struct{ UID, SecUID, Nickname, Avatar string }

func encodeKV(m map[string]string) string {
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+"="+url.QueryEscape(v))
	}
	return strings.Join(parts, "&")
}

// FetchUserInfo 直接请求 im/user/info（multipart sec_user_ids）。失败返回空表。
func FetchUserInfo(cookie string, secUids []string, deviceID string) map[string]User {
	out := map[string]User{}
	if len(secUids) == 0 {
		return out
	}
	if deviceID == "" {
		deviceID = "0"
	}
	q := map[string]string{
		"aid": "339757", "device_platform": "webapp", "version_code": "1.1.31", "version_name": "1.1.31",
		"device_id": deviceID, "channel": "channel_pc_web", "msToken": sign.MsToken(128),
	}
	queryStr := encodeKV(q)
	boundary := "----botFormBoundary" + sign.MsToken(16)
	secJSON, _ := json.Marshal(secUids)
	body := "--" + boundary + "\r\nContent-Disposition: form-data; name=\"sec_user_ids\"\r\n\r\n" +
		string(secJSON) + "\r\n--" + boundary + "--\r\n"
	ab := abogus.GetABogus(queryStr, body, ua, time.Now().UnixMilli())
	u := "https://imdesktop.douyin.com/aweme/v1/web/im/user/info/?" + queryStr + "&a_bogus=" + url.QueryEscape(ab)

	req, err := http.NewRequest("POST", u, strings.NewReader(body))
	if err != nil {
		return out
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	req.Header.Set("Referer", "https://imdesktop.douyin.com")
	req.Header.Set("Origin", "https://imdesktop.douyin.com")
	res, err := webHTTP.Do(req)
	if err != nil {
		return out
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	var j struct {
		Data []struct {
			UID         any    `json:"uid"`
			SecUID      string `json:"sec_uid"`
			Nickname    string `json:"nickname"`
			AvatarThumb struct {
				URLList []string `json:"url_list"`
			} `json:"avatar_thumb"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &j) != nil {
		return out
	}
	for _, d := range j.Data {
		if d.SecUID == "" {
			continue
		}
		avatar := ""
		if len(d.AvatarThumb.URLList) > 0 {
			avatar = d.AvatarThumb.URLList[0]
		}
		out[d.SecUID] = User{UID: uidStr(d.UID), SecUID: d.SecUID, Nickname: d.Nickname, Avatar: avatar}
	}
	return out
}

func uidStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatInt(int64(x), 10)
	}
	return ""
}

// ResolveUsers 带 sqlite 缓存：先查缓存，缺的才请求并写回。
func ResolveUsers(cookie string, secUids []string, deviceID string) map[string]User {
	out := map[string]User{}
	seen := map[string]bool{}
	var uniq []string
	for _, s := range secUids {
		if s != "" && !seen[s] {
			seen[s] = true
			uniq = append(uniq, s)
		}
	}
	if len(uniq) == 0 {
		return out
	}
	for k, v := range store.GetCachedUsers(uniq) {
		out[k] = User{UID: v.UID, SecUID: v.SecUID, Nickname: v.Nickname, Avatar: v.Avatar}
	}
	var missing []string
	for _, s := range uniq {
		if _, ok := out[s]; !ok {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		fetched := FetchUserInfo(cookie, missing, deviceID)
		var toCache []store.CachedUser
		for k, v := range fetched {
			out[k] = v
			toCache = append(toCache, store.CachedUser{SecUID: v.SecUID, UID: v.UID, Nickname: v.Nickname, Avatar: v.Avatar})
		}
		store.PutUsers(toCache)
	}
	return out
}

```

### `internal/store/cache.go`

```go
// Package store 本地缓存（modernc.org/sqlite，纯 Go，无 CGO，便于静态分发）。
package store

import (
	"database/sql"
	"strings"
	"sync"
	"time"

	"gobot/internal/config"

	_ "modernc.org/sqlite"
)

var (
	db   *sql.DB
	once sync.Once
	oerr error
)

func open() (*sql.DB, error) {
	once.Do(func() {
		d, err := sql.Open("sqlite", config.DBPath())
		if err != nil {
			oerr = err
			return
		}
		if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS users (
			sec_uid TEXT PRIMARY KEY, uid TEXT NOT NULL DEFAULT '',
			nickname TEXT NOT NULL DEFAULT '', avatar TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL DEFAULT 0)`); err != nil {
			oerr = err
			return
		}
		db = d
	})
	return db, oerr
}

// CachedUser 缓存的用户资料。
type CachedUser struct {
	SecUID, UID, Nickname, Avatar string
	UpdatedAt                     int64
}

// GetCachedUsers 批量取缓存。
func GetCachedUsers(secUids []string) map[string]CachedUser {
	out := make(map[string]CachedUser)
	if len(secUids) == 0 {
		return out
	}
	d, err := open()
	if err != nil || d == nil {
		return out
	}
	ph := strings.Repeat("?,", len(secUids))
	ph = ph[:len(ph)-1]
	args := make([]any, len(secUids))
	for i, s := range secUids {
		args[i] = s
	}
	rows, err := d.Query(`SELECT sec_uid, uid, nickname, avatar, updated_at FROM users WHERE sec_uid IN (`+ph+`)`, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var u CachedUser
		if rows.Scan(&u.SecUID, &u.UID, &u.Nickname, &u.Avatar, &u.UpdatedAt) == nil {
			out[u.SecUID] = u
		}
	}
	return out
}

// PutUsers 批量写入/更新。
func PutUsers(users []CachedUser) {
	if len(users) == 0 {
		return
	}
	d, err := open()
	if err != nil || d == nil {
		return
	}
	now := time.Now().Unix()
	stmt, err := d.Prepare(`INSERT INTO users (sec_uid, uid, nickname, avatar, updated_at) VALUES (?,?,?,?,?)
		ON CONFLICT(sec_uid) DO UPDATE SET uid=excluded.uid, nickname=excluded.nickname,
		avatar=excluded.avatar, updated_at=excluded.updated_at`)
	if err != nil {
		return
	}
	defer stmt.Close()
	for _, u := range users {
		_, _ = stmt.Exec(u.SecUID, u.UID, u.Nickname, u.Avatar, now)
	}
}

```


## K. 网关 (internal/gateway)

### `internal/gateway/gateway.go`

```go
// Package gateway bot 网关：WS 单向推事件 + HTTP POST /api/{动作} 发消息 + GET /health。
// 协议 1:1 对齐 TS 版 bot/src/gateway.ts（原生语义，不套 OneBot）。
//
//	ws://host:port/ws?access_token=令牌   连上后单向收事件（先一帧 hello）
//	POST http://host:port/api/{动作}       Authorization: Bearer 令牌
//	GET  http://host:port/health           无需令牌，看存活与账号状态
package gateway

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"gobot/internal/config"
	"gobot/internal/engine"
	"gobot/internal/media"
)

const protocolVersion = 1
const maxBody = 12 * 1024 * 1024 // 图片上限 5MB，base64 后约 6.7MB

type accountStatus struct {
	Account     string `json:"account"`
	Name        string `json:"name"`
	UID         string `json:"uid"`
	State       string `json:"state"` // offline/connecting/online/invalid/disabled
	Message     string `json:"message"`
	OnlineSince int64  `json:"online_since"`
}

// wsClient 每个 WS 连接一个带缓冲的发送队列 + 独立写 goroutine。
// 慢/半死的消费者只会撑满自己的队列（丢最旧的），绝不阻塞广播方（收包线程）。
type wsClient struct {
	conn *websocket.Conn
	out  chan []byte
	done chan struct{}
	once sync.Once
}

func newWsClient(conn *websocket.Conn, queueLimit int) *wsClient {
	if queueLimit <= 0 {
		queueLimit = 1000
	}
	c := &wsClient{conn: conn, out: make(chan []byte, queueLimit), done: make(chan struct{})}
	go c.writeLoop()
	return c
}

func (c *wsClient) writeLoop() {
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-c.done:
			return
		case b := <-c.out:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if c.conn.WriteMessage(websocket.TextMessage, b) != nil {
				c.close()
				return
			}
		case <-ping.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if c.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)) != nil {
				c.close()
				return
			}
		}
	}
}

// push 非阻塞入队；满了先丢最旧再塞，还满就放弃这条（不拖垮广播方）。
func (c *wsClient) push(b []byte) {
	select {
	case c.out <- b:
	default:
		select {
		case <-c.out:
		default:
		}
		select {
		case c.out <- b:
		default:
		}
	}
}

func (c *wsClient) close() {
	c.once.Do(func() {
		close(c.done)
		_ = c.conn.Close()
	})
}

// Sender 发送能力（*engine.Client 实现；便于测试替身）。
type Sender interface {
	SendTextEx(convID string, shortID uint64, text string) (engine.SendResult, error)
	SendImageResult(convID string, shortID uint64, img engine.ImageAsset) (engine.SendResult, error)
	SendEmojiResult(convID string, shortID uint64, e engine.EmojiSpec) (engine.SendResult, error)
	SendReplyResult(convID string, shortID uint64, r engine.ReplySpec) (engine.SendResult, error)
	SendVideoResult(convID string, shortID uint64, videoBytes, coverBytes []byte, width, height int) (engine.SendResult, error)
	Recall(convID string, shortID, serverMsgID uint64) error
	UploadImage(imageBytes []byte) (engine.ImageAsset, error)
	ResolveVideoURL(tkey string) (engine.VideoURL, error)
	ListConversations(count int) ([]engine.Conversation, error)
}

// Gateway 单账号网关。
type Gateway struct {
	cfg *config.BotConfig
	acc *config.Account
	eng Sender
	up  websocket.Upgrader
	srv *http.Server

	mu      sync.Mutex
	subs    map[*wsClient]struct{} // /ws 事件订阅者
	orisubs map[*wsClient]struct{} // /oriws 原始 protobuf 订阅者（调试用）

	stMu        sync.RWMutex
	state       string
	stateMsg    string
	onlineSince int64
}

// New 创建网关。
func New(cfg *config.BotConfig, acc *config.Account, eng Sender) *Gateway {
	return &Gateway{
		cfg: cfg, acc: acc, eng: eng,
		up:      websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }},
		subs:    map[*wsClient]struct{}{},
		orisubs: map[*wsClient]struct{}{},
		state:   "offline", stateMsg: "offline",
	}
}

// handler 路由（Start 与测试共用）。
func (g *Gateway) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", g.handleWs)
	mux.HandleFunc("/oriws", g.handleOriWs)
	mux.HandleFunc("/health", g.handleHealth)
	mux.HandleFunc("/img", media.ImageHandler) // 图片解密代理，共用本端口
	mux.HandleFunc("/video", g.handleVideo)    // 视频解密代理，共用本端口
	mux.HandleFunc("/api/", g.handleAPI)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, errMsg(404, "unknown path"))
	})
	return mux
}

// Start 监听 host:port（后台）。
func (g *Gateway) Start() error {
	ln, err := net.Listen("tcp", net.JoinHostPort(g.cfg.Host, strconv.Itoa(g.cfg.Port)))
	if err != nil {
		return err
	}
	media.SetProxyBase("http://" + g.linkAddr()) // 图片链接指向本端口
	g.srv = &http.Server{Handler: g.handler()}
	go func() { _ = g.srv.Serve(ln) }()
	return nil
}

// Stop 关闭 HTTP 服务并断开所有 WS 连接（优雅退出用）。
func (g *Gateway) Stop() {
	if g.srv != nil {
		_ = g.srv.Close()
	}
	g.mu.Lock()
	for c := range g.subs {
		c.close()
	}
	for c := range g.orisubs {
		c.close()
	}
	g.mu.Unlock()
}

// linkAddr 供图片链接用的地址：host 是 0.0.0.0/空时回落到 127.0.0.1。
func (g *Gateway) linkAddr() string {
	h := g.cfg.Host
	if h == "" || h == "0.0.0.0" || h == "::" {
		h = "127.0.0.1"
	}
	return net.JoinHostPort(h, strconv.Itoa(g.cfg.Port))
}

// Addr host:port，打印用。
func (g *Gateway) Addr() string { return net.JoinHostPort(g.cfg.Host, strconv.Itoa(g.cfg.Port)) }

// -- 状态 -------------------------------------------------------------------

// SetState 设置账号连接状态（offline/connecting/invalid…）。
func (g *Gateway) SetState(state, msg string) {
	g.stMu.Lock()
	g.state, g.stateMsg = state, msg
	g.stMu.Unlock()
}

// SetOnline 标记在线并记录时间。
func (g *Gateway) SetOnline() {
	g.stMu.Lock()
	g.state, g.stateMsg, g.onlineSince = "online", "online", time.Now().Unix()
	g.stMu.Unlock()
}

func (g *Gateway) list() []accountStatus {
	g.stMu.RLock()
	st, msg, since := g.state, g.stateMsg, g.onlineSince
	g.stMu.RUnlock()
	if !g.acc.Enabled {
		st, msg = "disabled", "disabled"
	}
	return []accountStatus{{Account: g.acc.ID, Name: g.acc.Name, UID: g.acc.UID, State: st, Message: msg, OnlineSince: since}}
}

// -- 事件下推 ---------------------------------------------------------------

// EmitMessage 推一条消息。别人发来的→message；自己发的→message_self（仅 emit_self 开启时）。
func (g *Gateway) EmitMessage(m engine.IncomingMessage) {
	if m.Direction == "sent" {
		if !g.cfg.EmitSelf {
			return
		}
		g.broadcast(map[string]any{
			"type": "message_self", "id": randID(), "time": time.Now().Unix(),
			"account": g.acc.ID, "self_uid": g.acc.UID,
			"conv_id": m.ConvID, "is_group": m.IsGroup, "text": m.Text,
		})
		return
	}
	ev := map[string]any{
		"type": "message", "id": randID(), "time": time.Now().Unix(),
		"account": g.acc.ID, "self_uid": g.acc.UID,
		"conv_id": m.ConvID, "is_group": m.IsGroup,
		"sender_id": m.SenderID, "sender_sec_uid": m.SenderMs4, "text": m.Text,
	}
	if m.Image != nil {
		ev["image"] = imageEvent(m.Image)
	}
	if m.Video != nil {
		ev["video"] = videoEvent(m.Video)
	}
	if m.Emoji != nil {
		ev["emoji"] = emojiEvent(m.Emoji)
	}
	g.broadcast(ev)
}

// emojiEvent 表情事件对象：展示名 + 明文图地址（可直接展示，无需解密）。
func emojiEvent(e *engine.ImEmoji) map[string]any {
	return map[string]any{
		"display_name": e.DisplayName, "image_type": e.ImageType,
		"width": e.Width, "height": e.Height, "url": e.URL, "sticker_id": e.StickerID,
	}
}

// videoEvent 视频事件对象：tkey/skey + 封面 poster（带解密链接）+ play_url（拿来即播的本地解密代理）。
// 原始可播 CDN 地址（仍是 CENC 密文）用 get_video_url 动作换。
func videoEvent(v *engine.ImVideo) map[string]any {
	ev := map[string]any{
		"tkey": v.Tkey, "skey": v.Skey, "md5": v.Md5,
		"width": v.Width, "height": v.Height, "check_pics": v.CheckPics,
		"play_url": media.VideoLink(v.Tkey, v.Skey), // 本地解密代理，<video src> 直接可播
	}
	if v.Poster != nil {
		ev["poster"] = imageEvent(v.Poster)
	}
	return ev
}

// imageEvent 把图片资源摊平成事件里的 image 对象：原始各档 url + 拿来即用的解密代理链接。
func imageEvent(im *engine.ImImage) map[string]any {
	linkOf := func(list []string) string {
		if len(list) > 0 {
			return media.ImageLink(list[0], im.Skey)
		}
		return ""
	}
	primary := im.PickURL()
	return map[string]any{
		"oid": im.Oid, "skey": im.Skey, "md5": im.Md5,
		"data_size": im.DataSize, "cover_width": im.CoverWidth, "cover_height": im.CoverHeight,
		"url":             primary,                           // 主 url（origin 优先），兼容旧字段
		"link":            media.ImageLink(primary, im.Skey), // 主解密链接，兼容旧字段
		"origin_url_list": im.OriginURLList,
		"large_url_list":  im.LargeURLList,
		"medium_url_list": im.MediumURLList,
		"thumb_url_list":  im.ThumbURLList,
		"links": map[string]any{ // 各档解密代理链接
			"origin": linkOf(im.OriginURLList),
			"large":  linkOf(im.LargeURLList),
			"medium": linkOf(im.MediumURLList),
			"thumb":  linkOf(im.ThumbURLList),
		},
	}
}

// EmitConnect 推账号已连接。
func (g *Gateway) EmitConnect(reason string) {
	g.broadcast(map[string]any{"type": "connect", "id": randID(), "time": time.Now().Unix(),
		"account": g.acc.ID, "self_uid": g.acc.UID, "reason": reason})
}

// EmitDisconnect 推账号断开。
func (g *Gateway) EmitDisconnect(reason string) {
	g.broadcast(map[string]any{"type": "disconnect", "id": randID(), "time": time.Now().Unix(),
		"account": g.acc.ID, "self_uid": g.acc.UID, "reason": reason})
}

func (g *Gateway) broadcast(ev any) { g.broadcastTo(g.subs, ev) }

func (g *Gateway) broadcastTo(subs map[*wsClient]struct{}, ev any) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	g.mu.Lock()
	clients := make([]*wsClient, 0, len(subs))
	for c := range subs {
		clients = append(clients, c)
	}
	g.mu.Unlock()
	for _, c := range clients {
		c.push(b)
	}
}

// EmitRaw 把收到的原始 protobuf 帧下推给 /oriws 订阅者（base64 + 解码树）。没人订阅就不解码。
func (g *Gateway) EmitRaw(payload []byte) {
	g.mu.Lock()
	n := len(g.orisubs)
	g.mu.Unlock()
	if n == 0 {
		return
	}
	g.broadcastTo(g.orisubs, map[string]any{
		"type":   "raw",
		"time":   time.Now().Unix(),
		"len":    len(payload),
		"b64":    base64.StdEncoding.EncodeToString(payload),
		"fields": engine.DecodeToTree(payload),
	})
}

// -- WS ---------------------------------------------------------------------

func (g *Gateway) handleWs(w http.ResponseWriter, r *http.Request) {
	conn, err := g.up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	if !g.tokenOK(extractToken(r)) {
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","msg":"token 无效"}`))
		_ = conn.Close()
		return
	}
	client := newWsClient(conn, g.cfg.QueueLimit)
	g.mu.Lock()
	g.subs[client] = struct{}{}
	g.mu.Unlock()

	hello, _ := json.Marshal(map[string]any{"type": "hello", "protocol": protocolVersion, "accounts": g.list()})
	client.push(hello)

	go func() {
		defer func() {
			g.mu.Lock()
			delete(g.subs, client)
			g.mu.Unlock()
			client.close()
		}()
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if strings.Contains(string(data), "ping") {
				client.push([]byte(`{"type":"pong"}`))
			}
		}
	}()
}

// handleOriWs 原始 protobuf 调试通道：连上后收到每一帧的 base64 + 解码树。
func (g *Gateway) handleOriWs(w http.ResponseWriter, r *http.Request) {
	conn, err := g.up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	if !g.tokenOK(extractToken(r)) {
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","msg":"token 无效"}`))
		_ = conn.Close()
		return
	}
	client := newWsClient(conn, g.cfg.QueueLimit)
	g.mu.Lock()
	g.orisubs[client] = struct{}{}
	g.mu.Unlock()
	client.push([]byte(`{"type":"hello","channel":"raw"}`))

	go func() {
		defer func() {
			g.mu.Lock()
			delete(g.orisubs, client)
			g.mu.Unlock()
			client.close()
		}()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
}

// -- HTTP -------------------------------------------------------------------

func (g *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	bots := len(g.subs)
	g.mu.Unlock()
	writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{
		"protocol": protocolVersion, "bots": bots, "accounts": g.list()}})
}

// handleVideo /video?tkey=&skey= 视频解密代理：tkey 换 CDN 地址 → 下载 CENC MP4 → skey 解密 → 出明文可播 MP4。
// 免鉴权（<video> 带不了 header）；下载地址由服务端用 tkey 换得，非调用方任意 URL，故无 SSRF 面。
// 用 ServeContent 支持 Range，播放器可拖动进度。
func (g *Gateway) handleVideo(w http.ResponseWriter, r *http.Request) {
	tkey := strings.TrimSpace(r.URL.Query().Get("tkey"))
	skey := strings.TrimSpace(r.URL.Query().Get("skey"))
	if tkey == "" || skey == "" {
		http.Error(w, "need tkey & skey", http.StatusBadRequest)
		return
	}
	u, err := g.eng.ResolveVideoURL(tkey)
	if err != nil {
		http.Error(w, "resolve: "+err.Error(), http.StatusBadGateway)
		return
	}
	data, err := media.FetchVideoAndDecrypt(u.MainURL, u.BackupURL, skey)
	if err != nil {
		http.Error(w, "err: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "video/mp4")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	http.ServeContent(w, r, "video.mp4", time.Time{}, bytes.NewReader(data))
}

func (g *Gateway) handleAPI(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/")
	if !knownAction(name) {
		writeJSON(w, 404, errMsg(404, "未知动作 "+name))
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, 405, errMsg(405, "POST only"))
		return
	}
	if !g.tokenOK(extractToken(r)) {
		writeJSON(w, 401, errMsg(401, "token 无效"))
		return
	}
	input := map[string]any{}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		writeJSON(w, 400, errMsg(400, "读请求体失败："+err.Error()))
		return
	}
	if s := strings.TrimSpace(string(raw)); s != "" {
		if err := json.Unmarshal([]byte(s), &input); err != nil {
			writeJSON(w, 400, errMsg(400, "请求体不是合法 JSON："+err.Error()))
			return
		}
	}
	writeJSON(w, 200, g.dispatch(name, input))
}

func knownAction(name string) bool {
	switch name {
	case "get_accounts", "send_text", "send_card", "send_action_card",
		"send_emoji", "send_image", "send_reply", "send_video", "upload_image", "recall",
		"get_video_url", "get_conversations":
		return true
	}
	return false
}

// decodeB64 解 base64（可带 data:...;base64, 前缀）。
func decodeB64(s string) ([]byte, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("空")
	}
	if strings.HasPrefix(s, "data:") {
		if i := strings.Index(s, ","); i > 0 {
			s = s[i+1:]
		}
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}

func (g *Gateway) dispatch(name string, in map[string]any) any {
	switch name {
	case "get_accounts":
		return okData(g.list())
	case "send_text":
		return g.actionSendText(in)
	case "send_image":
		return g.actionSendImage(in)
	case "upload_image":
		return g.actionUploadImage(in)
	case "send_emoji":
		return g.actionSendEmoji(in)
	case "send_reply":
		return g.actionSendReply(in)
	case "send_video":
		return g.actionSendVideo(in)
	case "recall":
		return g.actionRecall(in)
	case "get_video_url":
		return g.actionGetVideoURL(in)
	case "get_conversations":
		return g.actionGetConversations(in)
	default:
		// send_card / send_action_card
		return errMsg(500, "Go 版网关暂未实现该动作："+name)
	}
}

func (g *Gateway) actionSendVideo(in map[string]any) any {
	video, err := decodeB64(getStr(in, "data"))
	if err != nil {
		return errMsg(400, "data（视频 base64）: "+err.Error())
	}
	cover, err := decodeB64(getStr(in, "cover"))
	if err != nil {
		return errMsg(400, "cover（封面图 base64，必填）: "+err.Error())
	}
	convID, short, e := g.resolveConv(in)
	if e != "" {
		return errMsg(400, e)
	}
	res, err := g.eng.SendVideoResult(convID, short, video, cover, getIntV(in, "width"), getIntV(in, "height"))
	if err != nil {
		return errMsg(500, err.Error())
	}
	return okData(res)
}

func (g *Gateway) actionSendEmoji(in map[string]any) any {
	url := getStr(in, "url")
	if url == "" {
		url = getStr(in, "uri")
	}
	if url == "" {
		return errMsg(400, "缺少 url/uri（表情图地址）")
	}
	convID, short, e := g.resolveConv(in)
	if e != "" {
		return errMsg(400, e)
	}
	res, err := g.eng.SendEmojiResult(convID, short, engine.EmojiSpec{
		DisplayName: getStr(in, "display_name"), URL: url,
		Width: getIntV(in, "width"), Height: getIntV(in, "height"),
		ImageType: getStr(in, "image_type"), PackageID: getIntV(in, "package_id"),
	})
	if err != nil {
		return errMsg(500, err.Error())
	}
	return okData(res)
}

func (g *Gateway) actionSendReply(in map[string]any) any {
	text := getStr(in, "text")
	if text == "" {
		return errMsg(400, "text 不能为空")
	}
	refUID := getStr(in, "refmsg_uid")
	if refUID == "" {
		return errMsg(400, "缺少 refmsg_uid（被回复者 uid）")
	}
	convID, short, e := g.resolveConv(in)
	if e != "" {
		return errMsg(400, e)
	}
	res, err := g.eng.SendReplyResult(convID, short, engine.ReplySpec{
		Text: text, RefUID: refUID, RefSecUID: getStr(in, "refmsg_sec_uid"),
		Nickname: getStr(in, "nickname"), RefText: getStr(in, "refmsg_text"),
	})
	if err != nil {
		return errMsg(500, err.Error())
	}
	return okData(res)
}

func (g *Gateway) actionGetVideoURL(in map[string]any) any {
	tkey := getStr(in, "tkey")
	if tkey == "" {
		return errMsg(400, "缺少 tkey（视频消息里的 video.tkey）")
	}
	u, err := g.eng.ResolveVideoURL(tkey)
	if err != nil {
		return errMsg(500, err.Error())
	}
	// main_url/backup_url 仍是 CENC 密文；给了 skey 就一并回本地解密代理链接（拿来即播）。
	return okData(map[string]any{
		"main_url": u.MainURL, "backup_url": u.BackupURL, "expire_time": u.ExpireTime,
		"play_url": media.VideoLink(tkey, getStr(in, "skey")),
	})
}

// actionGetConversations 拉会话列表（群 + 单聊）。count 可选，默认 20。
func (g *Gateway) actionGetConversations(in map[string]any) any {
	convs, err := g.eng.ListConversations(getIntV(in, "count"))
	if err != nil {
		return errMsg(500, err.Error())
	}
	return okData(map[string]any{"conversations": convs, "count": len(convs)})
}

func (g *Gateway) actionRecall(in map[string]any) any {
	smid := engine.ParseUint(getStr(in, "server_msg_id"))
	if smid == 0 {
		return errMsg(400, "缺少 server_msg_id")
	}
	convID, short, e := g.resolveConv(in)
	if e != "" {
		return errMsg(400, e)
	}
	if err := g.eng.Recall(convID, short, smid); err != nil {
		return errMsg(500, err.Error())
	}
	return okData(map[string]any{"ok": true, "conv_id": convID})
}

func (g *Gateway) actionUploadImage(in map[string]any) any {
	raw, err := decodeB64(getStr(in, "data"))
	if err != nil {
		return errMsg(400, "data（图片 base64，可带 data:image/...;base64, 前缀）: "+err.Error())
	}
	asset, err := g.eng.UploadImage(raw)
	if err != nil {
		return errMsg(500, err.Error())
	}
	return okData(asset)
}

// resolveConv 解析发送目标：conv_id 或 to_uid，外加可选 conv_short_id。
func (g *Gateway) resolveConv(in map[string]any) (string, uint64, string) {
	convID := getStr(in, "conv_id")
	if convID == "" {
		if toUID := getStr(in, "to_uid"); toUID != "" {
			convID = engine.BuildConvID(g.acc.UID, toUID)
		}
	}
	if convID == "" {
		return "", 0, "缺少 conv_id 或 to_uid（to_uid 需为数字 uid）"
	}
	var short uint64
	if s := getStr(in, "conv_short_id"); s != "" {
		short, _ = strconv.ParseUint(s, 10, 64)
	}
	return convID, short, ""
}

func (g *Gateway) actionSendText(in map[string]any) any {
	text := getStr(in, "text")
	if text == "" {
		return errMsg(400, "text 不能为空")
	}
	convID, short, e := g.resolveConv(in)
	if e != "" {
		return errMsg(400, e)
	}
	res, err := g.eng.SendTextEx(convID, short, text)
	if err != nil {
		return errMsg(500, err.Error())
	}
	return okData(res)
}

func (g *Gateway) actionSendImage(in map[string]any) any {
	im, ok := in["image"].(map[string]any)
	if !ok {
		return errMsg(400, "缺少 image（upload_image 返回的对象）")
	}
	convID, short, e := g.resolveConv(in)
	if e != "" {
		return errMsg(400, e)
	}
	asset := engine.ImageAsset{
		Oid: getStr(im, "oid"), Skey: getStr(im, "skey"), Md5: getStr(im, "md5"),
		DataSize: getIntV(im, "data_size"), CoverWidth: getIntV(im, "cover_width"), CoverHeight: getIntV(im, "cover_height"),
	}
	if asset.Oid == "" || asset.Skey == "" {
		return errMsg(400, "image 缺少 oid/skey")
	}
	res, err := g.eng.SendImageResult(convID, short, asset)
	if err != nil {
		return errMsg(500, err.Error())
	}
	return okData(res)
}

// -- 工具 -------------------------------------------------------------------

func (g *Gateway) tokenOK(given string) bool {
	if g.cfg.Token == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(given), []byte(g.cfg.Token)) == 1
}

func extractToken(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return strings.TrimSpace(r.URL.Query().Get("access_token"))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	b, _ := json.Marshal(body)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func okData(data any) map[string]any             { return map[string]any{"code": 0, "data": data} }
func errMsg(code int, msg string) map[string]any { return map[string]any{"code": code, "msg": msg} }

func getStr(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatInt(int64(v), 10)
	}
	return ""
}

func getIntV(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case float64:
		return int(v)
	case string:
		n, _ := strconv.Atoi(v)
		return n
	}
	return 0
}

func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

```
