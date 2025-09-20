# 资源服务器示例

这个示例展示了如何使用 `xjp-oidc` 和 `xjp-oidc-axum` 创建一个资源服务器，使用 JWT 访问令牌保护 API 端点。

## 功能特性

- 🔐 JWT 访问令牌验证
- 🛡️ 路由级别的认证保护
- 👮 基于角色的访问控制（管理员权限）
- 🔄 多发行者支持
- 📝 声明提取和使用
- 🌐 CORS 配置
- 📊 请求追踪

## 项目结构

```
resource-server/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs
```

## 运行示例

### 1. 设置环境变量

```bash
export RUST_LOG=resource_server=debug,xjp_oidc=debug
```

### 2. 运行服务器

```bash
cd examples/resource-server
cargo run
```

服务器将在 `http://localhost:8081` 启动。

## API 端点

### 公开端点（无需认证）

- `GET /` - 根路由
- `GET /health` - 健康检查
- `GET /api/public` - 支持可选认证的公开端点

### 受保护端点（需要有效 JWT）

- `GET /api/profile` - 获取用户资料
- `GET /api/protected` - 访问受保护资源

### 管理员端点（需要有效 JWT + 管理员权限）

- `GET /api/admin/users` - 列出所有用户
- `GET /api/admin/settings` - 获取管理员设置

## 测试 API

### 1. 获取访问令牌

首先需要从认证服务器获取访问令牌。如果使用 auth-bff 示例：

```bash
# 1. 获取登录 URL
curl http://localhost:8080/api/auth/login-url

# 2. 完成 OAuth2 流程...

# 3. 从会话中获取令牌（实际项目中应该从认证响应中获取）
```

### 2. 测试公开端点

```bash
# 无认证访问
curl http://localhost:8081/api/public

# 响应：
# {
#   "message": "欢迎，匿名用户",
#   "authenticated": false,
#   "user_id": null
# }
```

### 3. 测试受保护端点

```bash
# 使用访问令牌
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://localhost:8081/api/profile

# 成功响应：
# {
#   "sub": "user123",
#   "email": "user123",
#   "scopes": ["openid", "profile", "email"],
#   "is_admin": false,
#   "auth_methods": ["pwd"]
# }

# 无令牌访问将返回 401
curl http://localhost:8081/api/profile
# 响应：401 Unauthorized
```

### 4. 测试管理员端点

```bash
# 需要管理员权限的令牌
curl -H "Authorization: Bearer ADMIN_ACCESS_TOKEN" \
     http://localhost:8081/api/admin/users

# 成功响应：
# [
#   {
#     "id": "1",
#     "email": "admin@example.com",
#     "name": "管理员",
#     "role": "admin"
#   }
# ]

# 非管理员令牌将返回 403
curl -H "Authorization: Bearer USER_ACCESS_TOKEN" \
     http://localhost:8081/api/admin/users
# 响应：403 Forbidden
```

## 配置说明

### JWT 验证器配置

```rust
// 支持多个发行者
let mut issuer_map = HashMap::new();
issuer_map.insert("xiaojin".to_string(), "https://auth.xiaojinpro.com".to_string());
issuer_map.insert("google".to_string(), "https://accounts.google.com".to_string());

// 创建验证器
let verifier = Arc::new(JwtVerifier::new(
    issuer_map,
    "resource-server-api".to_string(), // audience
    Arc::new(ReqwestHttpClient::default()),
    Arc::new(NoOpCache), // 生产环境应使用真实缓存
));
```

### 路由保护

```rust
// 1. 基本认证保护
.route("/api/protected", get(handler))
.layer(OidcLayer::new(verifier.clone()))

// 2. 管理员权限保护
.route("/api/admin/users", get(handler))
.route_layer(require_admin())
.layer(OidcLayer::new(verifier.clone()))

// 3. 可选认证
.route("/api/public", get(handler_with_optional_claims))
```

### 声明提取

```rust
// 基本声明
async fn handler(claims: VerifiedClaims) -> impl IntoResponse {
    // claims.sub - 用户 ID
    // claims.scope - 授权范围
    // claims.xjp_admin - 管理员标志
}

// 管理员声明
async fn admin_handler(admin: AdminClaims) -> impl IntoResponse {
    // 自动验证 xjp_admin == true
}

// 可选声明
async fn optional_handler(claims: OptionalClaims) -> impl IntoResponse {
    match claims.0 {
        Some(verified) => // 已认证
        None => // 未认证
    }
}
```

## 生产环境建议

1. **使用真实缓存**：将 `NoOpCache` 替换为 `MokaCacheImpl` 或 `LruCacheImpl`
2. **配置 CORS**：根据实际前端域名配置 CORS
3. **添加速率限制**：使用 tower-governor 等中间件
4. **完善错误处理**：自定义错误响应格式
5. **添加监控**：集成 Prometheus 指标
6. **配置 HTTPS**：使用反向代理提供 TLS

## 故障排查

### "Missing Authorization header"

确保请求头格式正确：
```
Authorization: Bearer YOUR_TOKEN
```

### "Invalid audience"

检查 JWT 的 `aud` 声明是否匹配验证器配置的 audience。

### "Token expired"

检查令牌是否过期，可能需要刷新令牌。

### "Invalid issuer"

确保令牌的 `iss` 声明在 issuer_map 中配置。

## 扩展示例

### 添加自定义中间件

```rust
use axum::middleware;

async fn auth_logger(
    claims: VerifiedClaims,
    req: Request,
    next: Next,
) -> Response {
    tracing::info!("User {} accessing {}", claims.sub, req.uri());
    next.run(req).await
}

// 使用
.route("/api/data", get(handler))
.layer(middleware::from_fn(auth_logger))
```

### 集成数据库

```rust
#[derive(Clone)]
struct AppState {
    verifier: Arc<JwtVerifier>,
    db: sqlx::PgPool,
}

async fn get_user_data(
    State(state): State<AppState>,
    claims: VerifiedClaims,
) -> Result<Json<UserData>, AppError> {
    let data = sqlx::query_as!(
        UserData,
        "SELECT * FROM user_data WHERE user_id = $1",
        claims.sub
    )
    .fetch_one(&state.db)
    .await?;
    
    Ok(Json(data))
}
```