# Auth BFF (Backend for Frontend) 服务

这是一个使用 `xjp-oidc` SDK 构建的极简 Auth BFF 服务，为前端应用提供安全的 OIDC 认证接口。

## 特性

- 🔐 完整的 OAuth2 授权码 + PKCE 流程
- 🔑 安全的服务器端会话管理
- 🚀 基于 Axum 的高性能实现
- 📝 RESTful API 设计
- 🛡️ 支持管理员权限验证
- 🚪 RP-Initiated Logout 支持

## API 端点

### 1. 获取登录 URL
```
GET /api/auth/login-url
```

响应:
```json
{
  "auth_url": "https://auth.example.com/authorize?..."
}
```

### 2. 处理回调
```
POST /api/auth/callback
Content-Type: application/json

{
  "callback_params": "code=xxx&state=yyy"
}
```

响应:
```json
{
  "success": true,
  "redirect_url": "http://localhost:3000"
}
```

### 3. 获取当前用户
```
GET /api/auth/user
```

响应:
```json
{
  "sub": "user123",
  "email": "user@example.com",
  "name": "张三",
  "picture": "https://example.com/avatar.jpg",
  "is_admin": true,
  "auth_methods": ["pwd", "otp"]
}
```

### 4. 登出
```
POST /api/auth/logout
```

### 5. 获取登出 URL
```
GET /api/auth/logout-url
```

响应:
```json
{
  "logout_url": "https://auth.example.com/logout?..."
}
```

### 6. 健康检查
```
GET /health
```

## 快速开始

### 1. 配置环境变量

复制 `.env.example` 到 `.env` 并配置:

```bash
cp .env.example .env
```

必须配置的变量:
- `OIDC_ISSUER`: OIDC 提供商的 issuer URL
- `CLIENT_ID`: OAuth2 客户端 ID

### 2. 运行服务

```bash
# 开发模式
cargo run

# 生产构建
cargo build --release
./target/release/auth-bff
```

服务将在 `http://localhost:8080` 启动。

## 前端集成示例

### 登录流程

```javascript
// 1. 获取登录 URL
const res = await fetch('/api/auth/login-url');
const { auth_url } = await res.json();

// 2. 重定向到认证服务器
window.location.href = auth_url;

// 3. 处理回调 (在回调页面)
const params = window.location.search;
const res = await fetch('/api/auth/callback', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ callback_params: params })
});

const { success, redirect_url } = await res.json();
if (success) {
  window.location.href = redirect_url;
}
```

### 获取用户信息

```javascript
const res = await fetch('/api/auth/user', {
  credentials: 'include'
});

if (res.ok) {
  const user = await res.json();
  console.log('当前用户:', user);
} else {
  // 未登录
  window.location.href = '/login';
}
```

### 登出流程

```javascript
// 方案 1: 仅清除本地会话
await fetch('/api/auth/logout', {
  method: 'POST',
  credentials: 'include'
});

// 方案 2: RP-Initiated Logout (同时登出 OIDC 提供商)
const res = await fetch('/api/auth/logout-url', {
  credentials: 'include'
});
const { logout_url } = await res.json();

if (logout_url) {
  window.location.href = logout_url;
} else {
  // 仅清除本地会话
  await fetch('/api/auth/logout', {
    method: 'POST',
    credentials: 'include'
  });
}
```

## 生产部署建议

### 1. 使用持久化会话存储

当前示例使用内存会话存储，生产环境建议使用 Redis:

```toml
[dependencies]
axum-sessions = "0.8"
async-redis-session = "0.2"
```

### 2. 配置 HTTPS

使用反向代理（如 Nginx）提供 HTTPS:

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 3. 配置 CORS

根据实际前端域名调整 CORS 配置:

```rust
CorsLayer::new()
    .allow_origin("https://app.example.com".parse::<HeaderValue>().unwrap())
    .allow_methods([Method::GET, Method::POST])
    .allow_headers([CONTENT_TYPE, AUTHORIZATION])
    .allow_credentials(true)
```

### 4. 监控和日志

- 使用 `tracing` 进行结构化日志
- 配置 Prometheus 指标收集
- 设置健康检查和告警

## 安全注意事项

1. **会话密钥**: 生产环境必须使用强随机密钥
2. **HTTPS**: 生产环境必须使用 HTTPS
3. **CORS**: 仅允许受信任的源
4. **会话超时**: 配置合理的会话过期时间
5. **令牌存储**: 敏感令牌仅存储在服务器端会话中

## 故障排查

### 登录后立即失效

检查 Cookie 配置:
- 确保前后端使用相同域名或配置正确的 Cookie domain
- 检查 SameSite 设置

### CORS 错误

- 确保 CORS 配置包含前端域名
- 检查是否启用 `allow_credentials`

### 会话丢失

- 检查反向代理是否正确转发 Cookie
- 确保会话密钥在所有实例间一致

## 许可证

MIT 或 Apache 2.0