# SDK 租户系统重构更新日志

## 版本：2.0.0 (Breaking Changes)

### 概述
为了与 SSO 主程序的简化保持一致，SDK 进行了重大重构，完全移除了子域名多租户支持，并引入了新的租户解析优先级系统。

### 🚨 破坏性变更

#### 1. 移除子域名模式
- **移除**: `TenantMode::Subdomain` 枚举值
- **移除**: `TenantConfig::subdomain()` 构造函数
- **移除**: `TenantConfig.base_domain` 字段
- **移除**: `TenantConfig::get_host_header()` 方法
- **影响**: 使用子域名模式的代码需要迁移到 ClientId 模式

#### 2. HTTP 客户端重构
- **移除**: `HttpClientWithHeaders` trait
- **移除**: Host 头部支持
- **新增**: `HttpClientWithAdminSupport` trait
- **新增**: 管理员覆盖头部支持 (`x-admin-key`, `x-admin-tenant`)
- **重命名**: `ReqwestHttpClientWithHeaders` → `ReqwestHttpClientWithAdminSupport`

### ✨ 新功能

#### 1. 租户解析优先级系统
新增 `TenantResolution` 结构体，支持三级优先级：
```rust
pub struct TenantResolution {
    pub client_id_tenant: Option<String>,      // 优先级 1
    pub admin_override_tenant: Option<String>, // 优先级 2
    pub default_tenant: Option<String>,        // 优先级 3
}
```

#### 2. 新的发现函数
```rust
pub async fn discover_with_tenant_resolution(
    issuer: &str,
    tenant_resolution: &TenantResolution,
    http: &dyn HttpClientWithAdminSupport,
    cache: &dyn Cache<String, OidcProviderMetadata>,
) -> Result<OidcProviderMetadata>
```

#### 3. OIDC 规范合规性改进
- **新增**: `subject_types_supported` 字段 (OIDC 必需字段)

### 🔄 迁移指南

#### 从子域名模式迁移到 ClientId 模式

**之前**：
```rust
let config = TenantConfig::subdomain(
    "xiaojinpro".to_string(),
    "auth.xiaojinpro.com".to_string()
);
```

**现在**：
```rust
let config = TenantConfig::client_id("xjp-web".to_string());
```

#### 使用新的租户解析系统

**推荐方式**：
```rust
let tenant_resolution = TenantResolution {
    client_id_tenant: Some("xjp-web".to_string()),
    admin_override_tenant: None,
    default_tenant: Some("xiaojinpro".to_string()),
};

let metadata = discover_with_tenant_resolution(
    issuer,
    &tenant_resolution,
    &http_client,
    &cache
).await?;
```

#### HTTP 客户端更新

**之前**：
```rust
use xjp_oidc::http_tenant::reqwest_tenant::ReqwestHttpClientWithHeaders;
let http_client = ReqwestHttpClientWithHeaders::new()?;
```

**现在**：
```rust
use xjp_oidc::http_tenant::reqwest_tenant::ReqwestHttpClientWithAdminSupport;
let http_client = ReqwestHttpClientWithAdminSupport::new()?;
// 或带管理员密钥
let http_client = ReqwestHttpClientWithAdminSupport::with_admin_key(admin_key)?;
```

### 📝 详细变更列表

#### 修改的文件
1. **tenant.rs**
   - 移除 Subdomain 枚举值和相关代码
   - 移除 base_domain 字段
   - 新增 TenantResolution 结构体
   - 更新测试用例

2. **http_tenant.rs**
   - 移除 HttpClientWithHeaders trait
   - 新增 HttpClientWithAdminSupport trait
   - 重构 HTTP 客户端实现
   - 支持管理员头部

3. **discovery_tenant.rs**
   - 新增 discover_with_tenant_resolution 函数
   - 更新现有函数以兼容新系统
   - 移除 Host 头部处理逻辑

4. **types.rs**
   - 新增 subject_types_supported 字段

5. **lib.rs**
   - 更新导出以反映新的类型和函数

6. **示例更新**
   - test-tenant-discovery/main.rs: 使用 ClientId 模式替代子域名模式

### ⚡ 性能改进
- 移除不必要的 Host 头部处理，简化 HTTP 请求流程
- 优化租户解析逻辑，减少不必要的验证

### 🔧 向后兼容性
- 保留 `discover_with_tenant` 函数用于旧代码兼容
- QueryParam 和 ClientId 模式保持不变
- Single 模式保持不变

### 📅 废弃计划
- 旧的 `discover_with_tenant` 函数将在下一个主版本中移除
- 建议立即迁移到新的 `discover_with_tenant_resolution` 函数

### 🎯 结果
SDK 现在与 SSO 主程序完全一致，移除了不必要的复杂性，同时保持了所有实际需要的功能。部署和维护都变得更加简单。