# SSE (Server-Sent Events) 支持

SDK 现已支持 SSE 功能，可用于实现扫码登录等需要实时状态更新的场景。

## 功能特性

- ✅ 创建登录会话（返回 login_id 和二维码 URL）
- ✅ 实时监听登录状态变化（通过 SSE）
- ✅ 轮询方式检查登录状态（作为备选方案）
- ✅ 支持登录超时和重连机制
- ✅ 完整的错误处理

## 使用方法

### 1. 启用 SSE 功能

在 `Cargo.toml` 中添加 `sse` 特性：

```toml
[dependencies]
xjp-oidc = { version = "1.0", features = ["sse"] }
```

### 2. 创建登录会话

```rust
use xjp_oidc::{sse::start_login_session, http::ReqwestHttpClient};

let http = ReqwestHttpClient::default();
let (login_id, qr_url) = start_login_session(
    "https://auth.example.com",
    "client-id",
    "https://app.example.com/callback",
    &http
).await?;

// 显示二维码让用户扫描
println!("请扫描二维码: {}", qr_url);
```

### 3. 监听登录状态（SSE 方式）

```rust
use xjp_oidc::sse::{subscribe_login_events, LoginMonitorConfig, LoginEvent, LoginStatus};
use futures_util::StreamExt;

let config = LoginMonitorConfig {
    issuer: "https://auth.example.com".to_string(),
    login_id: login_id.clone(),
    timeout_secs: Some(300),  // 5分钟超时
    max_reconnects: Some(3),  // 最多重连3次
};

let mut event_stream = subscribe_login_events(config).await?;

while let Some(event) = event_stream.next().await {
    match event {
        Ok(LoginEvent::StatusUpdate(state)) => {
            match state.status {
                LoginStatus::Scanned => println!("已扫描"),
                LoginStatus::Authorized => println!("已授权"),
                LoginStatus::Success => {
                    println!("登录成功！授权码: {:?}", state.code);
                    break;
                }
                LoginStatus::Failed => {
                    println!("登录失败: {:?}", state.error);
                    break;
                }
                LoginStatus::Expired => {
                    println!("登录过期");
                    break;
                }
                _ => {}
            }
        }
        _ => {}
    }
}
```

### 4. 检查登录状态（轮询方式）

如果不使用 SSE，可以通过轮询方式检查状态：

```rust
use xjp_oidc::sse::check_login_status;

loop {
    let state = check_login_status("https://auth.example.com", &login_id, &http).await?;
    
    match state.status {
        LoginStatus::Success => {
            println!("登录成功！");
            break;
        }
        LoginStatus::Failed | LoginStatus::Expired => {
            println!("登录失败或过期");
            break;
        }
        _ => {
            // 继续等待
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}
```

## 登录状态说明

- `Pending` - 等待用户扫描
- `Scanned` - 已扫描，等待确认
- `Authorized` - 已授权
- `Success` - 登录成功（包含授权码）
- `Failed` - 登录失败
- `Expired` - 登录会话过期

## 注意事项

1. SSE 功能仅在非 WASM 环境下可用（服务端专用）
2. 登录会话默认 5 分钟超时
3. SSE 连接包含自动重连机制
4. 建议同时实现 SSE 和轮询两种方式，以应对网络问题

## 运行示例

```bash
# 设置环境变量
export OIDC_CLIENT_ID=your-client-id
export OIDC_ISSUER=https://auth.xiaojinpro.com

# 运行 SSE 登录示例
cargo run --example sse-login --features sse
```