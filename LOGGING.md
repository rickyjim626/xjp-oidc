# 日志和追踪规范

本文档定义了 xjp-oidc SDK 的日志和追踪标准。

## 日志级别

使用标准的日志级别：

- **ERROR**: 错误，需要立即关注
- **WARN**: 警告，可能的问题
- **INFO**: 重要的业务事件
- **DEBUG**: 调试信息
- **TRACE**: 详细的追踪信息

## 结构化日志

### 字段规范

所有日志都应包含以下标准字段：

```rust
use tracing::{info, warn, error, debug, trace};

// 基础字段
info!(
    target: "xjp_oidc::auth",
    issuer = %issuer,
    client_id = %client_id,
    "开始授权流程"
);

// 错误日志
error!(
    target: "xjp_oidc::token",
    error = %e,
    issuer = %issuer,
    "Token 验证失败"
);

// 性能日志
info!(
    target: "xjp_oidc::perf",
    duration_ms = elapsed.as_millis() as u64,
    endpoint = %endpoint,
    status = %status_code,
    "HTTP 请求完成"
);
```

### 目标（Target）命名

使用模块路径作为 target：

- `xjp_oidc::auth` - 认证相关
- `xjp_oidc::token` - 令牌处理
- `xjp_oidc::discovery` - OIDC 发现
- `xjp_oidc::jwks` - JWKS 处理
- `xjp_oidc::cache` - 缓存操作
- `xjp_oidc::http` - HTTP 客户端
- `xjp_oidc::perf` - 性能指标

## Span 规范

使用 `tracing::instrument` 宏为函数添加 span：

```rust
#[tracing::instrument(
    name = "verify_id_token",
    skip(token, options),
    fields(
        issuer = %options.issuer,
        has_nonce = options.nonce.is_some(),
    )
)]
pub async fn verify_id_token(
    token: &str,
    options: VerifyOptions<'_>,
) -> Result<VerifiedIdToken> {
    // 函数实现
}
```

### Span 命名

- 使用函数名作为 span 名称
- 对于复杂操作，使用描述性名称
- 避免在 span 名称中包含动态数据

### Span 字段

- 包含关键的业务标识符
- 避免敏感信息
- 使用 `skip` 跳过大型或敏感参数

## 错误处理

### 错误日志格式

```rust
match result {
    Ok(value) => {
        debug!(
            target: "xjp_oidc::success",
            operation = "token_exchange",
            "操作成功"
        );
        Ok(value)
    }
    Err(e) => {
        error!(
            target: "xjp_oidc::error",
            error = %e,
            error_type = ?e,
            operation = "token_exchange",
            "操作失败"
        );
        Err(e)
    }
}
```

### 错误上下文

始终包含足够的上下文信息：

```rust
error!(
    target: "xjp_oidc::jwks",
    error = %e,
    jwks_uri = %jwks_uri,
    kid = %kid,
    retry_count = retry_count,
    "JWKS 获取失败"
);
```

## 性能追踪

### HTTP 请求

```rust
let start = std::time::Instant::now();
let result = http_client.get(url).await;
let duration = start.elapsed();

info!(
    target: "xjp_oidc::http",
    url = %url,
    method = "GET",
    duration_ms = duration.as_millis() as u64,
    status = result.as_ref().map(|r| r.status().as_u16()).ok(),
    "HTTP 请求完成"
);
```

### 缓存操作

```rust
debug!(
    target: "xjp_oidc::cache",
    cache_key = %key,
    cache_hit = hit,
    cache_type = "jwks",
    "缓存查询"
);
```

## 安全考虑

### 敏感信息

永远不要记录：
- 完整的访问令牌
- 客户端密钥
- 用户密码
- 完整的 ID Token

使用脱敏：

```rust
info!(
    target: "xjp_oidc::auth",
    token_prefix = &token[..8.min(token.len())],
    "使用令牌"
);
```

### PII（个人身份信息）

谨慎处理 PII：

```rust
info!(
    target: "xjp_oidc::user",
    user_id = %claims.sub,  // 用户 ID 通常可以
    // email = %claims.email,  // 避免记录邮箱
    "用户认证成功"
);
```

## 集成示例

### 应用初始化

```rust
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,xjp_oidc=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}
```

### 使用 OpenTelemetry

```rust
use opentelemetry::trace::TracerProvider;
use tracing_opentelemetry::OpenTelemetryLayer;

fn init_telemetry() {
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(opentelemetry_otlp::new_exporter().tonic())
        .install_batch(opentelemetry::runtime::Tokio)
        .expect("Failed to install tracer");
    
    let telemetry_layer = OpenTelemetryLayer::new(tracer);
    
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .with(telemetry_layer)
        .init();
}
```

## 日志配置

### 环境变量

```bash
# 基础配置
RUST_LOG=info,xjp_oidc=debug

# 详细调试
RUST_LOG=debug,xjp_oidc=trace,hyper=debug

# 生产环境
RUST_LOG=warn,xjp_oidc=info

# 特定模块
RUST_LOG=info,xjp_oidc::cache=debug,xjp_oidc::http=trace
```

### 日志格式

```bash
# 紧凑格式（默认）
RUST_LOG_FORMAT=compact

# 完整格式
RUST_LOG_FORMAT=full

# JSON 格式
RUST_LOG_FORMAT=json
```

## 最佳实践

1. **一致性**: 使用相同的字段名和格式
2. **上下文**: 总是包含足够的上下文
3. **性能**: 在热路径上使用 `trace!` 级别
4. **错误**: 错误日志应包含错误类型和消息
5. **业务事件**: 使用 `info!` 记录重要的业务事件

## 监控集成

### Prometheus 指标

```rust
use prometheus::{Counter, Histogram, Registry};

lazy_static! {
    static ref HTTP_REQUESTS: Counter = Counter::new(
        "xjp_oidc_http_requests_total",
        "Total number of HTTP requests"
    ).unwrap();
    
    static ref HTTP_DURATION: Histogram = Histogram::new(
        "xjp_oidc_http_duration_seconds",
        "HTTP request duration"
    ).unwrap();
}

// 使用
HTTP_REQUESTS.inc();
let timer = HTTP_DURATION.start_timer();
// ... 执行请求
timer.observe_duration();
```

### 日志聚合

推荐的日志聚合方案：

1. **Loki + Grafana**: 轻量级日志聚合
2. **Elasticsearch + Kibana**: 全文搜索和分析
3. **CloudWatch Logs**: AWS 环境
4. **Stackdriver**: GCP 环境

## 调试技巧

### 动态日志级别

```rust
// 在运行时更改日志级别
use tracing_subscriber::reload;

let (filter, reload_handle) = reload::Layer::new(
    tracing_subscriber::EnvFilter::from_default_env()
);

// 稍后更新
reload_handle.modify(|filter| {
    *filter = tracing_subscriber::EnvFilter::new("debug,xjp_oidc=trace")
}).unwrap();
```

### 条件日志

```rust
// 仅在调试模式下记录
if cfg!(debug_assertions) {
    debug!(
        target: "xjp_oidc::debug",
        详细信息 = ?complex_object,
        "调试信息"
    );
}
```

## 故障排查

常见问题的日志配置：

```bash
# Token 验证问题
RUST_LOG=info,xjp_oidc::token=trace,xjp_oidc::jwks=debug

# HTTP 连接问题
RUST_LOG=info,xjp_oidc::http=trace,hyper=debug,reqwest=debug

# 缓存问题
RUST_LOG=info,xjp_oidc::cache=trace

# 性能问题
RUST_LOG=info,xjp_oidc::perf=debug
```