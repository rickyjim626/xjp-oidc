# xjp-oidc SDK 新增功能说明

本次更新为 xjp-oidc SDK 添加了多项符合 OAuth2/OIDC 标准的新功能，以对齐服务端的完整能力。

## 实现状态

✅ **已完成实现的功能**：
- Token Introspection (RFC 7662)
- Token Revocation (RFC 7009)  
- Refresh Token
- UserInfo Endpoint
- DCR Client Configuration  
- 多租户系统重构（移除子域名支持）

所有功能均已通过编译和基本测试。

## 新增功能列表

### 1. Token Introspection (RFC 7662)
检查 token 的当前状态和元数据。

```rust
use xjp_oidc::{introspect_token, IntrospectRequest};

let response = introspect_token(IntrospectRequest {
    issuer: "https://auth.example.com".into(),
    client_id: "my-client".into(),
    client_secret: Some("secret".into()),
    token: "access_token".into(),
    token_type_hint: Some("access_token".into()),
    token_endpoint_auth_method: None,
}, &http).await?;

if response.active {
    println!("Token is active, expires at: {:?}", response.exp);
}
```

### 2. Token Revocation (RFC 7009)
吊销已颁发的 token。

```rust
use xjp_oidc::revoke_token;

revoke_token(
    "https://auth.example.com",
    "my-client",
    Some("secret"),
    "refresh_token_to_revoke",
    Some("refresh_token"),
    None,
    &http
).await?;
```

### 3. Refresh Token
使用 refresh token 获取新的 access token。

```rust
use xjp_oidc::{refresh_token, RefreshTokenRequest};

let tokens = refresh_token(RefreshTokenRequest {
    issuer: "https://auth.example.com".into(),
    client_id: "my-client".into(),
    client_secret: Some("secret".into()),
    refresh_token: "refresh_token".into(),
    scope: Some("openid profile".into()),
    token_endpoint_auth_method: None,
}, &http).await?;
```

### 4. UserInfo Endpoint
获取用户信息。

```rust
use xjp_oidc::get_userinfo;

let userinfo = get_userinfo(
    "https://auth.example.com",
    "access_token",
    &http
).await?;

println!("User: {} ({})", userinfo.name.unwrap_or_default(), userinfo.sub);
```

### 5. DCR Client Configuration
获取已注册客户端的配置。

```rust
use xjp_oidc::get_client_config;

let config = get_client_config(
    "https://auth.example.com",
    "my-client-id",
    "registration_access_token",
    &http
).await?;
```

### 6. 多租户支持重构

#### 移除子域名模式
为了与 SSO 主程序的简化保持一致，子域名模式已被完全移除。

#### 新的租户解析优先级系统
引入 `TenantResolution` 结构体，支持三级优先级：

```rust
use xjp_oidc::tenant::TenantResolution;
use xjp_oidc::discovery_tenant::discover_with_tenant_resolution;

let tenant_resolution = TenantResolution {
    client_id_tenant: Some("xjp-web".to_string()),      // 优先级 1
    admin_override_tenant: None,                        // 优先级 2  
    default_tenant: Some("xiaojinpro".to_string()),    // 优先级 3
};

let metadata = discover_with_tenant_resolution(
    issuer,
    &tenant_resolution,
    &http_client,
    &cache
).await?;
```

#### ClientId 模式（推荐）
ClientId 模式会在发现 URL 中追加 `client_id` 查询参数：

```rust
let config = TenantConfig::client_id("xjp-web".to_string());
let url = "https://auth.example.com/.well-known/openid-configuration";
let tenant_url = config.apply_to_url(url)?;
// 结果: https://auth.example.com/.well-known/openid-configuration?client_id=xjp-web
```

## 新增的类型

### OidcProviderMetadata 新增字段
- `introspection_endpoint`: Token introspection 端点
- `revocation_endpoint`: Token revocation 端点
- `frontchannel_logout_supported`: 前端通道登出支持
- `frontchannel_logout_session_supported`: 前端通道会话登出支持
- `backchannel_logout_supported`: 后端通道登出支持
- `backchannel_logout_session_supported`: 后端通道会话登出支持
- `subject_types_supported`: 支持的主体类型（OIDC 必需字段）

### 新增请求/响应类型
- `IntrospectRequest` / `IntrospectResponse`
- `RefreshTokenRequest`
- `UserInfo`
- `ClientConfig`

## 已知限制

### HttpClient Trait 限制
当前的 `HttpClient` trait 不支持带授权头的 GET 请求，导致：
- UserInfo 端点使用 POST 请求（OIDC 规范允许）
- DCR GET 端点使用 POST 请求作为临时解决方案

建议在未来版本中扩展 `HttpClient` trait 以支持：
```rust
async fn get_value_with_auth(
    &self,
    url: &str,
    auth_header: Option<(&str, &str)>
) -> Result<Value, HttpClientError>;
```

## 破坏性变更

`OidcProviderMetadata` 结构体新增了多个必填字段，这会导致：
- 直接构造该结构体的代码需要更新
- 现有的测试可能需要添加新字段

建议使用 serde 反序列化或提供 builder 模式来创建该结构体。

## 示例程序

查看 `examples/new_features_example.rs` 了解所有新功能的使用示例。

```bash
cargo run --example new_features_example -p xjp-oidc
```