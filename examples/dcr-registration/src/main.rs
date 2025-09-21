//! DCR (Dynamic Client Registration) 自助报备工具
//!
//! 用于向 OIDC 提供商注册新的客户端应用

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Select};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use xjp_oidc::{
    discover, register_if_needed, ClientRegistrationResult, NoOpCache, RegisterRequest,
    ReqwestHttpClient,
};

#[derive(Parser)]
#[command(author, version, about = "DCR 客户端注册工具", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 注册新客户端
    Register {
        /// OIDC 发行者 URL
        #[arg(short, long)]
        issuer: Option<String>,

        /// 配置文件路径
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// 列出已注册的客户端
    List,

    /// 显示客户端详情
    Show {
        /// 客户端名称
        name: String,
    },

    /// 导出客户端配置
    Export {
        /// 客户端名称
        name: String,

        /// 输出格式 (json, toml, env)
        #[arg(short, long, default_value = "json")]
        format: String,
    },

    /// 创建示例配置文件
    Init,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientConfig {
    /// 客户端名称（用于本地标识）
    name: String,
    /// OIDC 发行者 URL
    issuer: String,
    /// 应用类型
    application_type: String,
    /// 重定向 URI 列表
    redirect_uris: Vec<String>,
    /// 登出后重定向 URI 列表
    post_logout_redirect_uris: Vec<String>,
    /// 授权类型
    grant_types: Vec<String>,
    /// 令牌端点认证方法
    token_endpoint_auth_method: String,
    /// 请求的权限范围
    scope: String,
    /// 联系人邮箱
    contacts: Vec<String>,
    /// 客户端名称（显示用）
    client_name: String,
    /// Logo URI
    logo_uri: Option<String>,
    /// 客户端 URI
    client_uri: Option<String>,
    /// 服务条款 URI
    tos_uri: Option<String>,
    /// 隐私政策 URI
    policy_uri: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            name: "my-app".to_string(),
            issuer: "https://auth.example.com".to_string(),
            application_type: "web".to_string(),
            redirect_uris: vec!["https://app.example.com/callback".to_string()],
            post_logout_redirect_uris: vec!["https://app.example.com".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            token_endpoint_auth_method: "none".to_string(),
            scope: "openid profile email".to_string(),
            contacts: vec!["admin@example.com".to_string()],
            client_name: "My Application".to_string(),
            logo_uri: None,
            client_uri: Some("https://app.example.com".to_string()),
            tos_uri: None,
            policy_uri: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SavedClient {
    config: ClientConfig,
    response: ClientRegistrationResult,
    registered_at: chrono::DateTime<chrono::Utc>,
}

struct DcrTool {
    http_client: Arc<ReqwestHttpClient>,
    cache: Arc<NoOpCache>,
    data_dir: PathBuf,
}

impl DcrTool {
    fn new() -> Result<Self> {
        let dirs =
            ProjectDirs::from("com", "xiaojinpro", "dcr-tool").context("无法确定配置目录")?;

        let data_dir = dirs.data_dir().to_path_buf();
        fs::create_dir_all(&data_dir)?;

        Ok(Self {
            http_client: Arc::new(ReqwestHttpClient::default()),
            cache: Arc::new(NoOpCache),
            data_dir,
        })
    }

    fn clients_file(&self) -> PathBuf {
        self.data_dir.join("clients.json")
    }

    fn load_clients(&self) -> Result<HashMap<String, SavedClient>> {
        let path = self.clients_file();
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let data = fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&data)?)
    }

    fn save_clients(&self, clients: &HashMap<String, SavedClient>) -> Result<()> {
        let path = self.clients_file();
        let data = serde_json::to_string_pretty(clients)?;
        fs::write(&path, data)?;
        Ok(())
    }

    async fn register_interactive(&self, issuer: Option<String>) -> Result<()> {
        println!("{}", "=== DCR 客户端注册向导 ===".blue().bold());
        println!();

        let theme = ColorfulTheme::default();

        // 基本信息
        let issuer = issuer.unwrap_or_else(|| {
            Input::with_theme(&theme)
                .with_prompt("OIDC 发行者 URL")
                .default("https://auth.xiaojinpro.com".to_string())
                .interact_text()
                .unwrap()
        });

        let name = Input::<String>::with_theme(&theme)
            .with_prompt("客户端名称（本地标识）")
            .validate_with(|input: &String| {
                if input.is_empty() {
                    Err("名称不能为空")
                } else if input.contains(" ") {
                    Err("名称不能包含空格")
                } else {
                    Ok(())
                }
            })
            .interact_text()?;

        let client_name = Input::<String>::with_theme(&theme)
            .with_prompt("应用显示名称")
            .default(name.clone())
            .interact_text()?;

        // 应用类型
        let app_types = vec!["web", "native", "spa"];
        let app_type_idx = Select::with_theme(&theme)
            .with_prompt("应用类型")
            .items(&app_types)
            .default(0)
            .interact()?;
        let application_type = app_types[app_type_idx].to_string();

        // 重定向 URI
        println!("\n{}", "配置重定向 URI（至少一个）".yellow());
        let mut redirect_uris = vec![];
        loop {
            let uri = Input::<String>::with_theme(&theme)
                .with_prompt("重定向 URI")
                .default(if redirect_uris.is_empty() {
                    "https://app.example.com/callback".to_string()
                } else {
                    String::new()
                })
                .allow_empty(true)
                .interact_text()?;

            if uri.is_empty() && !redirect_uris.is_empty() {
                break;
            } else if !uri.is_empty() {
                redirect_uris.push(uri);
                println!(
                    "  {} 已添加 {} 个重定向 URI",
                    "✓".green(),
                    redirect_uris.len()
                );
            }
        }

        // 登出重定向 URI
        let add_logout = Confirm::with_theme(&theme)
            .with_prompt("是否配置登出后重定向 URI？")
            .default(true)
            .interact()?;

        let post_logout_redirect_uris = if add_logout {
            let mut uris = vec![];
            loop {
                let uri = Input::<String>::with_theme(&theme)
                    .with_prompt("登出后重定向 URI")
                    .default(if uris.is_empty() {
                        "https://app.example.com".to_string()
                    } else {
                        String::new()
                    })
                    .allow_empty(true)
                    .interact_text()?;

                if uri.is_empty() {
                    break;
                } else {
                    uris.push(uri);
                }
            }
            uris
        } else {
            vec![]
        };

        // 认证方法
        let auth_methods = vec!["none", "client_secret_basic", "client_secret_post"];
        let auth_method_idx = Select::with_theme(&theme)
            .with_prompt("令牌端点认证方法")
            .items(&auth_methods)
            .default(0)
            .interact()?;
        let token_endpoint_auth_method = auth_methods[auth_method_idx].to_string();

        // 权限范围
        let scopes = vec![
            "openid",
            "profile",
            "email",
            "phone",
            "address",
            "offline_access",
        ];
        let selected_scopes = MultiSelect::with_theme(&theme)
            .with_prompt("选择权限范围")
            .items(&scopes)
            .defaults(&[true, true, true, false, false, false])
            .interact()?;

        let scope = selected_scopes
            .iter()
            .map(|&idx| scopes[idx])
            .collect::<Vec<_>>()
            .join(" ");

        // 联系人
        let contact_email = Input::<String>::with_theme(&theme)
            .with_prompt("联系人邮箱")
            .validate_with(|input: &String| {
                if input.contains('@') {
                    Ok(())
                } else {
                    Err("请输入有效的邮箱地址")
                }
            })
            .interact_text()?;

        // 可选 URI
        let client_uri = Input::<String>::with_theme(&theme)
            .with_prompt("客户端主页 URL（可选）")
            .allow_empty(true)
            .interact_text()?;

        let logo_uri = Input::<String>::with_theme(&theme)
            .with_prompt("Logo URL（可选）")
            .allow_empty(true)
            .interact_text()?;

        // 构建配置
        let config = ClientConfig {
            name,
            issuer: issuer.clone(),
            application_type,
            redirect_uris,
            post_logout_redirect_uris,
            grant_types: vec!["authorization_code".to_string()],
            token_endpoint_auth_method,
            scope,
            contacts: vec![contact_email],
            client_name,
            logo_uri: if logo_uri.is_empty() {
                None
            } else {
                Some(logo_uri)
            },
            client_uri: if client_uri.is_empty() {
                None
            } else {
                Some(client_uri)
            },
            tos_uri: None,
            policy_uri: None,
        };

        // 显示配置
        println!("\n{}", "=== 注册配置预览 ===".cyan().bold());
        println!("{}", serde_json::to_string_pretty(&config)?);

        let confirm = Confirm::with_theme(&theme)
            .with_prompt("确认注册？")
            .default(true)
            .interact()?;

        if !confirm {
            println!("{}", "已取消注册".yellow());
            return Ok(());
        }

        // 执行注册
        self.register_client(config).await
    }

    async fn register_client(&self, config: ClientConfig) -> Result<()> {
        println!("\n{}", "正在注册客户端...".blue());

        // 发现端点
        let discovery = discover(
            &config.issuer,
            self.http_client.as_ref(),
            self.cache.as_ref(),
        )
        .await?;

        let _registration_endpoint = discovery
            .registration_endpoint
            .context("此 OIDC 提供商不支持动态客户端注册")?;

        // 构建注册请求
        let request = RegisterRequest {
            application_type: Some(config.application_type.clone()),
            redirect_uris: config.redirect_uris.clone(),
            post_logout_redirect_uris: Some(config.post_logout_redirect_uris.clone()),
            grant_types: config.grant_types.clone(),
            token_endpoint_auth_method: config.token_endpoint_auth_method.clone(),
            scope: config.scope.clone(),
            contacts: Some(config.contacts.clone()),
            client_name: Some(config.client_name.clone()),
            software_id: Some(config.name.clone()), // 使用 name 作为 software_id
        };

        // 执行注册
        let response = register_if_needed(
            &config.issuer,
            "your-initial-access-token", // TODO: 从配置或环境变量获取
            request,
            self.http_client.as_ref(),
        )
        .await?;

        // 保存结果
        let mut clients = self.load_clients()?;
        clients.insert(
            config.name.clone(),
            SavedClient {
                config: config.clone(),
                response: response.clone(),
                registered_at: chrono::Utc::now(),
            },
        );
        self.save_clients(&clients)?;

        // 显示结果
        println!("\n{}", "✅ 客户端注册成功！".green().bold());
        println!();
        println!("{}: {}", "客户端 ID".bold(), response.client_id.green());
        if let Some(secret) = &response.client_secret {
            println!("{}: {}", "客户端密钥".bold(), secret.red());
            println!(
                "\n{}",
                "⚠️  请妥善保存客户端密钥，此密钥不会再次显示！"
                    .yellow()
                    .bold()
            );
        }

        println!("\n{}", "注册信息已保存到:".blue());
        println!("  {}", self.clients_file().display());

        Ok(())
    }

    async fn list_clients(&self) -> Result<()> {
        let clients = self.load_clients()?;

        if clients.is_empty() {
            println!("{}", "没有已注册的客户端".yellow());
            println!("\n运行 {} 注册新客户端", "dcr register".cyan());
            return Ok(());
        }

        println!("{}", "=== 已注册的客户端 ===".blue().bold());
        println!();

        for (name, client) in &clients {
            println!("{} {}", "•".green(), name.bold());
            println!("  客户端 ID: {}", client.response.client_id);
            println!("  发行者: {}", client.config.issuer);
            println!(
                "  注册时间: {}",
                client.registered_at.format("%Y-%m-%d %H:%M:%S")
            );
            println!();
        }

        Ok(())
    }

    async fn show_client(&self, name: &str) -> Result<()> {
        let clients = self.load_clients()?;

        let client = clients
            .get(name)
            .context(format!("未找到客户端: {}", name))?;

        println!("{}", format!("=== 客户端: {} ===", name).blue().bold());
        println!();

        println!("{}", "注册配置:".green());
        println!("{}", serde_json::to_string_pretty(&client.config)?);

        println!("\n{}", "注册响应:".green());
        println!("{}", serde_json::to_string_pretty(&client.response)?);

        println!("\n{}", "元信息:".green());
        println!(
            "注册时间: {}",
            client.registered_at.format("%Y-%m-%d %H:%M:%S")
        );

        Ok(())
    }

    async fn export_client(&self, name: &str, format: &str) -> Result<()> {
        let clients = self.load_clients()?;

        let client = clients
            .get(name)
            .context(format!("未找到客户端: {}", name))?;

        match format {
            "json" => {
                let export = serde_json::json!({
                    "client_id": client.response.client_id,
                    "client_secret": client.response.client_secret,
                    "issuer": client.config.issuer,
                    "redirect_uris": client.config.redirect_uris,
                    "scope": client.config.scope,
                });
                println!("{}", serde_json::to_string_pretty(&export)?);
            }

            "toml" => {
                let export = format!(
                    r#"[oidc]
client_id = "{}"
client_secret = {}
issuer = "{}"
redirect_uri = "{}"
scope = "{}"
"#,
                    client.response.client_id,
                    client
                        .response
                        .client_secret
                        .as_ref()
                        .map(|s| format!("\"{}\"", s))
                        .unwrap_or_else(|| "null".to_string()),
                    client.config.issuer,
                    client
                        .config
                        .redirect_uris
                        .first()
                        .unwrap_or(&String::new()),
                    client.config.scope,
                );
                println!("{}", export);
            }

            "env" => {
                println!("OIDC_CLIENT_ID={}", client.response.client_id);
                if let Some(secret) = &client.response.client_secret {
                    println!("OIDC_CLIENT_SECRET={}", secret);
                }
                println!("OIDC_ISSUER={}", client.config.issuer);
                println!(
                    "OIDC_REDIRECT_URI={}",
                    client
                        .config
                        .redirect_uris
                        .first()
                        .unwrap_or(&String::new())
                );
                println!("OIDC_SCOPE={}", client.config.scope);
            }

            _ => {
                return Err(anyhow::anyhow!("不支持的格式: {}", format));
            }
        }

        Ok(())
    }

    async fn init_config(&self) -> Result<()> {
        let config = ClientConfig::default();
        let toml = toml::to_string_pretty(&config)?;

        let path = PathBuf::from("dcr-config.toml");
        if path.exists() {
            let confirm = Confirm::new()
                .with_prompt("配置文件已存在，是否覆盖？")
                .default(false)
                .interact()?;

            if !confirm {
                return Ok(());
            }
        }

        fs::write(&path, toml)?;
        println!("{}", "✅ 已创建示例配置文件: dcr-config.toml".green());
        println!("\n编辑配置文件后运行:");
        println!("  {}", "dcr register --config dcr-config.toml".cyan());

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dcr_registration=info,xjp_oidc=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    let cli = Cli::parse();
    let tool = DcrTool::new()?;

    match cli.command {
        Commands::Register { issuer, config } => {
            if let Some(config_path) = config {
                let config_str = fs::read_to_string(config_path)?;
                let config: ClientConfig = toml::from_str(&config_str)?;
                tool.register_client(config).await?;
            } else {
                tool.register_interactive(issuer).await?;
            }
        }

        Commands::List => {
            tool.list_clients().await?;
        }

        Commands::Show { name } => {
            tool.show_client(&name).await?;
        }

        Commands::Export { name, format } => {
            tool.export_client(&name, &format).await?;
        }

        Commands::Init => {
            tool.init_config().await?;
        }
    }

    Ok(())
}

// 添加 chrono 依赖
use chrono;
