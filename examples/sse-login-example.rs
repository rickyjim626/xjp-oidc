//! SSE 登录流程示例
//! 
//! 这个示例演示如何使用 SSE 实现实时登录状态监控，
//! 通常用于扫码登录等需要实时反馈的场景。

use std::error::Error;
use xjp_oidc::{
    prelude::*,
    http::ReqwestHttpClient,
};

#[cfg(feature = "sse")]
use futures_util::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 配置环境
    let issuer = std::env::var("OIDC_ISSUER")
        .unwrap_or_else(|_| "https://auth.xiaojinpro.com".to_string());
    let client_id = std::env::var("OIDC_CLIENT_ID")
        .expect("请设置 OIDC_CLIENT_ID 环境变量");
    let redirect_uri = std::env::var("OIDC_REDIRECT_URI")
        .unwrap_or_else(|_| "https://app.example.com/callback".to_string());

    // 创建 HTTP 客户端
    let http = ReqwestHttpClient::default();

    // 启动登录会话
    println!("正在启动登录会话...");
    let (login_id, qr_url) = start_login_session(
        &issuer,
        &client_id,
        &redirect_uri,
        &http
    ).await?;

    println!("登录会话已创建！");
    println!("Login ID: {}", login_id);
    println!("二维码 URL: {}", qr_url);
    println!("请扫描二维码或在浏览器中打开链接进行登录\n");

    // 方式1：使用 SSE 监听登录状态
    #[cfg(feature = "sse")]
    {
        println!("开始监听登录状态（SSE）...");
        
        let config = LoginMonitorConfig {
            issuer: issuer.clone(),
            login_id: login_id.clone(),
            timeout_secs: Some(300), // 5分钟超时
            max_reconnects: Some(3),
        };

        let mut event_stream = subscribe_login_events(config).await?;

        while let Some(event) = event_stream.next().await {
            match event {
                Ok(LoginEvent::StatusUpdate(state)) => {
                    println!("[状态更新] {:?}", state.status);
                    
                    match state.status {
                        LoginStatus::Scanned => {
                            println!("✓ 二维码已扫描，请在微信中确认登录");
                        }
                        LoginStatus::Authorized => {
                            println!("✓ 用户已授权");
                        }
                        LoginStatus::Success => {
                            println!("✓ 登录成功！");
                            if let Some(code) = state.code {
                                println!("授权码: {}", code);
                                println!("\n现在可以使用授权码换取 token:");
                                println!("await exchange_code(...);");
                            }
                            break;
                        }
                        LoginStatus::Failed => {
                            println!("✗ 登录失败");
                            if let Some(error) = state.error {
                                println!("错误信息: {}", error);
                            }
                            break;
                        }
                        LoginStatus::Expired => {
                            println!("✗ 登录会话已过期");
                            break;
                        }
                        _ => {}
                    }
                }
                Ok(LoginEvent::Heartbeat) => {
                    // 心跳事件，通常不需要处理
                }
                Ok(LoginEvent::Close) => {
                    println!("SSE 连接已关闭");
                    break;
                }
                Ok(LoginEvent::Error(msg)) => {
                    println!("SSE 错误: {}", msg);
                }
                Err(e) => {
                    println!("事件流错误: {}", e);
                    break;
                }
            }
        }
    }

    // 方式2：轮询登录状态（作为 SSE 的备选方案）
    #[cfg(not(feature = "sse"))]
    {
        println!("开始轮询登录状态...");
        
        let mut attempts = 0;
        let max_attempts = 300; // 5分钟，每秒轮询一次
        
        loop {
            attempts += 1;
            if attempts > max_attempts {
                println!("✗ 登录超时");
                break;
            }

            let state = check_login_status(&issuer, &login_id, &http).await?;
            
            match state.status {
                LoginStatus::Pending => {
                    // 继续等待
                    print!(".");
                    std::io::Write::flush(&mut std::io::stdout())?;
                }
                LoginStatus::Scanned => {
                    println!("\n✓ 二维码已扫描，请在微信中确认登录");
                }
                LoginStatus::Success => {
                    println!("\n✓ 登录成功！");
                    if let Some(code) = state.code {
                        println!("授权码: {}", code);
                    }
                    break;
                }
                LoginStatus::Failed => {
                    println!("\n✗ 登录失败");
                    if let Some(error) = state.error {
                        println!("错误信息: {}", error);
                    }
                    break;
                }
                LoginStatus::Expired => {
                    println!("\n✗ 登录会话已过期");
                    break;
                }
                _ => {}
            }
            
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }

    println!("\n登录流程结束");
    Ok(())
}

// 辅助函数：处理授权码
#[allow(dead_code)]
async fn handle_authorization_code(
    code: &str,
    issuer: &str,
    client_id: &str,
    redirect_uri: &str,
    http: &dyn HttpClient,
) -> Result<(), Box<dyn Error>> {
    println!("正在使用授权码换取 token...");
    
    // 这里应该包含 PKCE verifier，从之前的流程中获取
    let tokens = exchange_code(ExchangeCode {
        issuer: issuer.to_string(),
        client_id: client_id.to_string(),
        code: code.to_string(),
        redirect_uri: redirect_uri.to_string(),
        code_verifier: None, // 实际使用时应该提供 PKCE verifier
        client_secret: None,
        token_endpoint_auth_method: None,
    }, http).await?;
    
    println!("Token 获取成功！");
    println!("Access Token: {}", tokens.access_token);
    if let Some(refresh_token) = &tokens.refresh_token {
        println!("Refresh Token: {}", refresh_token);
    }
    
    // 验证 ID Token
    let cache = NoOpCache;
    let metadata = discover(issuer, http, &cache).await?;
    verify_id_token(&tokens.id_token, &metadata, client_id, None).await?;
    println!("ID Token 验证成功！");
    
    Ok(())
}