use clap::{Parser, Subcommand};
use xjp_oidc::types::VerifyOptions;
use xjp_oidc::{discover, fetch_jwks, verify_id_token, NoOpCache, ReqwestHttpClient};

#[derive(Parser)]
#[command(name = "xjp-oidc-cli")]
#[command(about = "XJP-OIDC Discovery and Verification CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Discover OpenID Configuration from issuer
    Discover {
        /// Issuer URL
        #[arg(short, long)]
        issuer: String,

        /// Output format
        #[arg(short, long, default_value = "pretty")]
        format: OutputFormat,
    },

    /// Fetch and display JWKS from issuer
    Jwks {
        /// Issuer URL
        #[arg(short, long)]
        issuer: String,

        /// Output format
        #[arg(short, long, default_value = "pretty")]
        format: OutputFormat,
    },

    /// Verify an ID token and display claims
    VerifyId {
        /// Issuer URL
        #[arg(short, long)]
        issuer: String,

        /// Expected audience
        #[arg(short, long)]
        audience: String,

        /// ID token to verify
        #[arg(short, long)]
        token: String,

        /// Expected nonce (optional)
        #[arg(short, long)]
        nonce: Option<String>,

        /// Output format
        #[arg(short, long, default_value = "pretty")]
        format: OutputFormat,
    },
}

#[derive(Clone, Debug)]
enum OutputFormat {
    Pretty,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pretty" => Ok(OutputFormat::Pretty),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!("Invalid format: {}. Use 'pretty' or 'json'", s)),
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let http = ReqwestHttpClient::default();
    let cache = NoOpCache;

    match cli.command {
        Commands::Discover { issuer, format } => match discover(&issuer, &http, &cache).await {
            Ok(metadata) => match format {
                OutputFormat::Pretty => {
                    println!("OpenID Configuration for {}", issuer);
                    println!("{}", "=".repeat(50));
                    println!(
                        "Authorization endpoint: {}",
                        metadata.authorization_endpoint
                    );
                    println!("Token endpoint:         {}", metadata.token_endpoint);
                    println!("JWKS URI:              {}", metadata.jwks_uri);

                    if let Some(userinfo) = &metadata.userinfo_endpoint {
                        println!("UserInfo endpoint:      {}", userinfo);
                    }
                    if let Some(end_session) = &metadata.end_session_endpoint {
                        println!("End session endpoint:   {}", end_session);
                    }
                    if let Some(registration) = &metadata.registration_endpoint {
                        println!("Registration endpoint:  {}", registration);
                    }

                    println!("\nSupported features:");
                    if let Some(response_types) = &metadata.response_types_supported {
                        println!("  Response types: {}", response_types.join(", "));
                    }
                    if let Some(grant_types) = &metadata.grant_types_supported {
                        println!("  Grant types: {}", grant_types.join(", "));
                    }
                    if let Some(scopes) = &metadata.scopes_supported {
                        println!("  Scopes: {}", scopes.join(", "));
                    }
                    if let Some(methods) = &metadata.code_challenge_methods_supported {
                        println!("  PKCE methods: {}", methods.join(", "));
                    }
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&metadata).unwrap());
                }
            },
            Err(e) => {
                eprintln!("Error discovering metadata: {}", e);
                std::process::exit(1);
            }
        },

        Commands::Jwks { issuer, format } => {
            // First discover to get JWKS URI
            match discover(&issuer, &http, &cache).await {
                Ok(metadata) => match fetch_jwks(&metadata.jwks_uri, &http, &cache).await {
                    Ok(jwks) => match format {
                        OutputFormat::Pretty => {
                            println!("JWKS for {}", issuer);
                            println!("{}", "=".repeat(50));
                            println!("Number of keys: {}", jwks.keys.len());

                            for (i, key) in jwks.keys.iter().enumerate() {
                                println!("\nKey #{}:", i + 1);
                                println!("  Key ID (kid): {}", key.kid);
                                println!("  Key Type (kty): {}", key.kty);
                                println!("  Algorithm (alg): {}", key.alg.as_deref().unwrap_or("not specified"));
                                println!("  Use: {}", key.use_);

                                if key.kty == "RSA" {
                                    if let Some(n) = &key.n {
                                        let display_n = if n.len() > 20 { &n[..20] } else { n };
                                        println!("  RSA Modulus (n): {}...", display_n);
                                    }
                                    if let Some(e) = &key.e {
                                        println!("  RSA Exponent (e): {}", e);
                                    }
                                }
                            }
                        }
                        OutputFormat::Json => {
                            println!("{}", serde_json::to_string_pretty(&jwks).unwrap());
                        }
                    },
                    Err(e) => {
                        eprintln!("Error fetching JWKS: {}", e);
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!("Error discovering metadata: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::VerifyId {
            issuer,
            audience,
            token,
            nonce,
            format,
        } => {
            // Use a simple cache for JWKS
            let cache = xjp_oidc::MokaCacheImpl::new(10);

            match verify_id_token(
                &token,
                VerifyOptions {
                    issuer: &issuer,
                    audience: &audience,
                    nonce: nonce.as_deref(),
                    max_age_sec: None,
                    clock_skew_sec: Some(120),
                    http: &http,
                    cache: &cache,
                },
            )
            .await
            {
                Ok(claims) => match format {
                    OutputFormat::Pretty => {
                        println!("ID Token verified successfully!");
                        println!("{}", "=".repeat(50));
                        println!("Subject (sub):     {}", claims.sub);
                        println!("Issuer (iss):      {}", claims.iss);
                        println!("Audience (aud):    {}", claims.aud);
                        println!("Issued at (iat):   {}", claims.iat);
                        println!("Expires at (exp):  {}", claims.exp);

                        if let Some(nonce) = &claims.nonce {
                            println!("Nonce:             {}", nonce);
                        }
                        if let Some(sid) = &claims.sid {
                            println!("Session ID (sid):  {}", sid);
                        }

                        println!("\nProfile claims:");
                        if let Some(name) = &claims.name {
                            println!("  Name:  {}", name);
                        }
                        if let Some(email) = &claims.email {
                            println!("  Email: {}", email);
                        }

                        println!("\nCustom XJP claims:");
                        println!("  Admin (xjp_admin): {:?}", claims.xjp_admin);
                        println!("  Auth methods (amr): {:?}", claims.amr);
                        println!("  Auth time: {:?}", claims.auth_time);
                    }
                    OutputFormat::Json => {
                        println!("{}", serde_json::to_string_pretty(&claims).unwrap());
                    }
                },
                Err(e) => {
                    eprintln!("Token verification failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
