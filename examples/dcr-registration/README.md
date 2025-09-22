# DCR 自助报备工具

这是一个命令行工具，用于向支持 [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) 的 OIDC 提供商动态注册客户端应用。

## 功能特性

- 🚀 交互式注册向导
- 📝 支持配置文件批量注册
- 💾 本地保存注册信息
- 🔍 查看和管理已注册客户端
- 📤 多种格式导出配置
- 🎨 彩色终端输出

## OIDC 基础信息（小金保测试环境）

- **Issuer/Discovery**：`https://auth.xiaojinpro.com`（Caddy 反向代理并自动签发证书，HTTP `:80` 会 308 重定向，内部仍转发至 `127.0.0.1:8081`），标准 `/.well-known/openid-configuration` 已启用，核心端点包括 `/oauth2/authorize`、`/oauth2/token`、`/oidc/userinfo`、`/.well-known/jwks.json`、`/oauth2/revoke`、`/oauth2/introspect`
- **客户端凭据**：`xjp-web`（confidential，`client_secret_basic`，支持 `client_secret_post`/`none` 但未启用，Secret=`dev_secret_change_in_production` 仅限测试）、`xjp-cli`（public，`none`，无 Client Secret）
- **重定向 URI**：`xjp-web` → `http://localhost:3000/auth/callback`、`https://app.example.com/auth/callback`；`xjp-cli` → `http://localhost:9876/callback`
- **默认 Scope**：`openid profile email offline_access`
- **Token Claims**：`aud` 等于请求的 `client_id`；额外支持 `amr`（如 `["wechat_qr"]`）、`xjp_admin`（布尔）、`auth_time`（UNIX 秒）等自定义声明，并按用户记录返回 `scope`、`sid`、`name`、`email`、`picture`
- **环境集成**：已配置微信登录（AppID=`wx04971a76992f4fd0`，回调 `https://auth.xiaojinpro.com/auth/wechat/callback`）；CORS 允许来源 `https://auth.xiaojinpro.com`；对外提供 HTTPS，8081 端口仍保留向内兼容；`/metrics` 默认开放；如需测试账号需手动在 `users` 表或后台创建
- **高级功能**：启用动态注册 `POST /oauth2/register`（`FEATURE_DCR_ENABLED=true`）；可选客户端审批（默认关闭）；多租户路由 `/oidc/*` 已预置，当前仅默认租户 `xiaojinpro`
- **后续建议**：如需正式回调域名或登出回调，可在后台更新 `oauth_clients` 并同步 `.env.production` CORS 列表；需 HTTPS 时可通过反向代理（如 Caddy/Nginx）终止 TLS，并更新 Issuer/Redirect URI；必要时生成初始注册令牌（`client_registration_tokens` 表存哈希）以配合 DCR

## 安装

```bash
cd examples/dcr-registration
cargo install --path .
```

或直接运行：

```bash
cargo run -- [命令]
```

## 使用方法

### 1. 交互式注册

最简单的方式是使用交互式向导：

```bash
dcr register
```

向导会引导你完成：

- 输入 OIDC 发行者 URL
- 配置应用基本信息
- 选择应用类型（web/native/spa）
- 添加重定向 URI
- 选择认证方法
- 选择权限范围

### 2. 使用配置文件注册

首先生成示例配置：

```bash
dcr init
```

这会创建 `dcr-config.toml` 文件：

```toml
name = "my-app"
issuer = "https://auth.example.com"
application_type = "web"
redirect_uris = ["https://app.example.com/callback"]
post_logout_redirect_uris = ["https://app.example.com"]
grant_types = ["authorization_code"]
token_endpoint_auth_method = "none"
scope = "openid profile email"
contacts = ["admin@example.com"]
client_name = "My Application"
client_uri = "https://app.example.com"
```

编辑配置后执行注册：

```bash
dcr register --config dcr-config.toml
```

### 3. 管理已注册客户端

列出所有客户端：

```bash
dcr list
```

查看客户端详情：

```bash
dcr show my-app
```

### 4. 导出客户端配置

导出为 JSON：

```bash
dcr export my-app --format json
```

导出为 TOML：

```bash
dcr export my-app --format toml
```

导出为环境变量：

```bash
dcr export my-app --format env > .env
```

## 配置说明

### 应用类型

- `web` - 传统 Web 应用（服务器端渲染）
- `native` - 原生应用（移动/桌面）
- `spa` - 单页应用（纯前端）

### 认证方法

- `none` - 公共客户端（PKCE）
- `client_secret_basic` - HTTP Basic 认证
- `client_secret_post` - POST 请求体认证

### 权限范围

标准 OIDC 范围：

- `openid` - 必需，获取 ID Token
- `profile` - 用户基本信息
- `email` - 邮箱地址
- `phone` - 电话号码
- `address` - 地址信息
- `offline_access` - 刷新令牌

## 数据存储

注册信息保存在：

- macOS: `~/Library/Application Support/com.xiaojinpro.dcr-tool/clients.json`
- Linux: `~/.local/share/dcr-tool/clients.json`
- Windows: `%APPDATA%\xiaojinpro\dcr-tool\data\clients.json`

## 安全注意事项

1. **客户端密钥**：如果注册时分配了客户端密钥，请立即保存。密钥只显示一次！

2. **存储安全**：本地存储的客户端信息包含敏感数据，请确保文件权限正确。

3. **传输安全**：始终使用 HTTPS 的 OIDC 端点。

## 故障排查

### "此 OIDC 提供商不支持动态客户端注册"

提供商未启用 DCR 功能。检查发现文档或联系管理员。

### "注册失败：401 Unauthorized"

某些提供商需要初始访问令牌。请查看提供商文档。

### "redirect_uri 验证失败"

确保重定向 URI 符合提供商的要求：

- 使用 HTTPS（本地开发可能允许 HTTP）
- 不包含片段（#）
- 路径正确

## 高级用法

### 批量注册

创建多个配置文件并使用脚本批量注册：

```bash
#!/bin/bash
for config in configs/*.toml; do
    echo "注册 $config..."
    dcr register --config "$config"
done
```

### 集成到 CI/CD

在部署流程中自动注册：

```yaml
- name: Register OIDC Client
  run: |
    dcr register --config production.toml
    dcr export $APP_NAME --format env > .env
```

### 使用环境变量

设置默认发行者：

```bash
export OIDC_ISSUER=https://auth.example.com
dcr register  # 将使用环境变量中的发行者
```

## 示例场景

### 1. 注册 SPA 应用

```bash
dcr register
# 选择 application_type: spa
# 设置 redirect_uris: https://app.example.com/callback
# 选择 token_endpoint_auth_method: none
```

### 2. 注册移动应用

```bash
dcr register
# 选择 application_type: native
# 设置 redirect_uris: com.example.app://callback
# 启用 PKCE（自动）
```

### 3. 注册后端服务

```bash
dcr register
# 选择 application_type: web
# 选择 token_endpoint_auth_method: client_secret_basic
# 添加 client_credentials 到 grant_types
```

## 贡献

欢迎提交问题和改进建议！
