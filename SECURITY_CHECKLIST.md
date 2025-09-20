# 安全检查清单

此清单用于确保 xjp-oidc SDK 的安全性。在每个版本发布前，请确保完成所有检查项。

## 发布前安全检查

### 代码审查

- [ ] 所有新代码都经过至少一人审查
- [ ] 审查者检查了潜在的安全问题
- [ ] 没有硬编码的密钥或凭据
- [ ] 敏感信息不会被记录到日志
- [ ] 输入验证充分且严格

### 依赖安全

- [ ] 运行 `cargo audit` 无高危漏洞
- [ ] 运行 `cargo deny check` 通过
- [ ] 所有依赖都是最新的稳定版本
- [ ] 检查了新增依赖的安全历史
- [ ] 依赖的许可证兼容

### JWT 和加密

- [ ] JWT 签名始终被验证
- [ ] 使用安全的算法（RS256, ES256）
- [ ] 拒绝 none 算法
- [ ] 时钟偏移设置合理（默认 60 秒）
- [ ] 密钥长度符合标准（RSA ≥ 2048）

### 网络安全

- [ ] 默认只允许 HTTPS
- [ ] 证书验证默认开启
- [ ] 支持自定义 CA 证书
- [ ] HTTP 客户端有超时设置
- [ ] 防止 SSRF 攻击

### 会话和状态

- [ ] State 参数用于防止 CSRF
- [ ] Nonce 用于防止重放攻击
- [ ] PKCE 实现正确
- [ ] 会话数据加密存储
- [ ] 合理的会话超时

### 错误处理

- [ ] 错误信息不泄露敏感信息
- [ ] 区分用户错误和系统错误
- [ ] 适当的错误日志记录
- [ ] 防止时序攻击

### 测试覆盖

- [ ] 安全相关功能有单元测试
- [ ] 集成测试覆盖主要场景
- [ ] 测试了错误情况
- [ ] 模糊测试（如适用）

## 运行时安全建议

### 部署配置

```toml
# 推荐的安全配置
[security]
# 只允许 HTTPS
require_https = true

# 启用证书验证
verify_certificates = true

# 设置合理的超时
http_timeout_seconds = 30

# 限制重定向次数
max_redirects = 5

# 启用日志脱敏
sanitize_logs = true
```

### 环境变量

```bash
# 生产环境必需的安全设置
export RUST_LOG=info  # 避免过于详细的日志
export SSL_CERT_FILE=/path/to/ca-bundle.crt  # 自定义 CA
export OIDC_STRICT_MODE=true  # 严格模式
```

### 监控指标

需要监控的安全相关指标：

1. **认证失败率**
   - 异常高的失败率可能表示攻击
   - 基准线：< 5%

2. **Token 验证错误**
   - 签名验证失败
   - 过期 token
   - 无效的 issuer

3. **网络错误**
   - SSL 错误
   - 连接超时
   - DNS 解析失败

4. **性能指标**
   - JWKS 获取时间
   - Token 验证时间
   - 缓存命中率

## 事件响应

### 安全事件分级

1. **P0 - 严重**
   - 远程代码执行
   - 认证绕过
   - 密钥泄露

2. **P1 - 高**
   - DoS 漏洞
   - 信息泄露
   - 权限提升

3. **P2 - 中**
   - 非关键信息泄露
   - 性能问题
   - 配置错误

### 响应流程

1. **发现** → 2. **评估** → 3. **修复** → 4. **通知** → 5. **总结**

### 联系方式

- 安全团队邮箱：security@xiaojinpro.com
- 紧急热线：+86-xxx-xxxx-xxxx
- PGP 密钥：[链接]

## 合规性

### 标准符合性

- [ ] OAuth 2.0 (RFC 6749)
- [ ] OpenID Connect Core 1.0
- [ ] PKCE (RFC 7636)
- [ ] JWT (RFC 7519)
- [ ] JWS (RFC 7515)

### 安全认证

- [ ] OWASP Top 10 检查
- [ ] CWE/SANS Top 25 检查
- [ ] PCI DSS（如适用）
- [ ] SOC 2（如适用）

## 工具链

### 必需工具

```bash
# 安装安全工具
cargo install cargo-audit
cargo install cargo-deny
cargo install cargo-outdated
cargo install cargo-license

# 扫描工具
brew install grype syft

# 代码分析
cargo clippy
cargo fmt
```

### CI/CD 集成

```yaml
# GitHub Actions 示例
- name: Security Scan
  run: |
    cargo audit
    cargo deny check
    ./scripts/security-scan.sh
```

## 更新此清单

此清单应定期更新：

- 每季度审查一次
- 发生安全事件后
- 主要版本发布前
- 行业最佳实践变化时

最后更新：2024-01-20