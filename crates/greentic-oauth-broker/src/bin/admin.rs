use anyhow::Context;
use clap::{Parser, Subcommand};
use greentic_config::{ConfigLayer, ConfigResolver};
use greentic_oauth_broker::admin::DesiredAppRequest;
use greentic_oauth_core::config::OAuthClientOptions;
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(name = "greentic-oauth-admin", version)]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    base_url: String,
    /// Override config file path (defaults to ~/.config/greentic/config.toml and .greentic/config.toml)
    #[arg(long)]
    config: Option<PathBuf>,
    /// Print resolved config and exit
    #[arg(long)]
    explain_config: bool,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    Providers,
    Start {
        provider: String,
        #[arg(long)]
        tenant: String,
    },
    Ensure {
        provider: String,
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        file: PathBuf,
    },
    Plan {
        provider: String,
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        file: PathBuf,
    },
    Teams {
        #[command(subcommand)]
        cmd: TeamsCommand,
    },
}

#[derive(Subcommand)]
enum TeamsCommand {
    Plan {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        file: PathBuf,
    },
    Ensure {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        file: PathBuf,
    },
    Install {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        team_id: String,
    },
    RemoveTeam {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        team_id: String,
    },
    GetSpec {
        #[arg(long)]
        tenant: String,
    },
}

fn load_cli_config_layer(path: &Option<PathBuf>) -> anyhow::Result<ConfigLayer> {
    let Some(path) = path else {
        return Ok(ConfigLayer::default());
    };

    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file at {}", path.display()))?;
    let parsed = match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse JSON config file at {}", path.display()))?,
        _ => toml::from_str(&contents)
            .with_context(|| format!("failed to parse TOML config file at {}", path.display()))?,
    };

    Ok(parsed)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let legacy_warnings = apply_legacy_env_aliases();
    let cli_overrides = load_cli_config_layer(&cli.config)?;
    let resolved = ConfigResolver::new()
        .with_cli_overrides(cli_overrides)
        .load()?;

    if cli.explain_config {
        let report =
            greentic_config::explain(&resolved.config, &resolved.provenance, &resolved.warnings);
        println!("{}", report.text);
        return Ok(());
    }

    for warning in legacy_warnings.iter() {
        eprintln!("{warning}");
    }
    for warning in resolved.warnings.iter() {
        eprintln!("{warning}");
    }

    let client = OAuthClientOptions::new(
        resolved.config.network.clone(),
        resolved.config.telemetry.clone(),
    )
    .build_blocking_http_client()?;
    match cli.cmd {
        Command::Providers => {
            let res: serde_json::Value = client
                .get(format!("{}/admin/providers", cli.base_url))
                .send()?
                .json()?;
            println!("{}", serde_json::to_string_pretty(&res)?);
        }
        Command::Start { provider, tenant } => {
            let res: serde_json::Value = client
                .post(format!(
                    "{}/admin/providers/{}/start?tenant={}",
                    cli.base_url, provider, tenant
                ))
                .send()?
                .json()?;
            println!("{}", serde_json::to_string_pretty(&res)?);
        }
        Command::Ensure {
            provider,
            tenant,
            file,
        } => {
            let data = fs::read_to_string(file)?;
            let mut request: DesiredAppRequest = serde_json::from_str(&data)?;
            request.tenant = tenant;
            let res: serde_json::Value = client
                .post(format!(
                    "{}/admin/providers/{}/ensure",
                    cli.base_url, provider
                ))
                .json(&request)
                .send()?
                .json()?;
            println!("{}", serde_json::to_string_pretty(&res)?);
        }
        Command::Plan {
            provider,
            tenant,
            file,
        } => {
            let data = fs::read_to_string(file)?;
            let mut request: DesiredAppRequest = serde_json::from_str(&data)?;
            request.tenant = tenant;
            let res: serde_json::Value = client
                .post(format!(
                    "{}/admin/providers/{}/plan",
                    cli.base_url, provider
                ))
                .json(&request)
                .send()?
                .json()?;
            println!("{}", serde_json::to_string_pretty(&res)?);
        }
        Command::Teams { cmd } => match cmd {
            TeamsCommand::Plan { tenant, file } => {
                let data = fs::read_to_string(file)?;
                let mut request: DesiredAppRequest = serde_json::from_str(&data)?;
                request.tenant = tenant;
                let res: serde_json::Value = client
                    .post(format!(
                        "{}/admin/messaging/teams/tenant/plan",
                        cli.base_url
                    ))
                    .json(&request)
                    .send()?
                    .json()?;
                print_plan_summary(&res);
                println!("{}", serde_json::to_string_pretty(&res)?);
            }
            TeamsCommand::Ensure { tenant, file } => {
                let data = fs::read_to_string(file)?;
                let mut request: DesiredAppRequest = serde_json::from_str(&data)?;
                request.tenant = tenant;
                let res: serde_json::Value = client
                    .post(format!(
                        "{}/admin/messaging/teams/tenant/ensure",
                        cli.base_url
                    ))
                    .json(&request)
                    .send()?
                    .json()?;
                println!("{}", serde_json::to_string_pretty(&res)?);
            }
            TeamsCommand::Install { tenant, team_id } => {
                let payload = serde_json::json!({ "tenant": tenant, "team_id": team_id });
                let res: serde_json::Value = client
                    .post(format!(
                        "{}/admin/messaging/teams/tenant/install",
                        cli.base_url
                    ))
                    .json(&payload)
                    .send()?
                    .json()?;
                println!("{}", serde_json::to_string_pretty(&res)?);
            }
            TeamsCommand::RemoveTeam { tenant, team_id } => {
                let res: serde_json::Value = client
                    .delete(format!(
                        "{}/admin/messaging/teams/tenant/team/{}?tenant={}",
                        cli.base_url, team_id, tenant
                    ))
                    .send()?
                    .json()?;
                println!("{}", serde_json::to_string_pretty(&res)?);
            }
            TeamsCommand::GetSpec { tenant } => {
                let res: serde_json::Value = client
                    .get(format!(
                        "{}/admin/messaging/teams/tenant/spec?tenant={}",
                        cli.base_url, tenant
                    ))
                    .send()?
                    .json()?;
                println!("{}", serde_json::to_string_pretty(&res)?);
            }
        },
    }
    Ok(())
}

fn apply_legacy_env_aliases() -> Vec<String> {
    let mut warnings = Vec::new();

    if std::env::var_os("GREENTIC_NETWORK_PROXY_URL").is_none()
        && let Ok(value) = std::env::var("OAUTH_HTTP_PROXY")
    {
        set_env_var("GREENTIC_NETWORK_PROXY_URL", &value);
        warnings.push(
            "OAUTH_HTTP_PROXY is deprecated; set GREENTIC_NETWORK_PROXY_URL via greentic-config instead"
                .into(),
        );
    }

    if std::env::var_os("OAUTH_NO_PROXY").is_some() {
        warnings.push(
            "OAUTH_NO_PROXY is deprecated and ignored; no_proxy is no longer supported".into(),
        );
    }

    if std::env::var_os("GREENTIC_NETWORK_TLS_MODE").is_none() {
        for legacy in ["OAUTH_TLS_INSECURE", "ALLOW_INSECURE"] {
            if let Ok(value) = std::env::var(legacy) {
                if is_truthy_flag(&value) {
                    set_env_var("GREENTIC_NETWORK_TLS_MODE", "disabled");
                    warnings.push(format!(
                        "{legacy} is deprecated; set GREENTIC_NETWORK_TLS_MODE=disabled via greentic-config instead"
                    ));
                }
                break;
            }
        }
    }

    if std::env::var_os("GREENTIC_NETWORK_CONNECT_TIMEOUT_MS").is_none()
        && let Ok(value) = std::env::var("OAUTH_CONNECT_TIMEOUT_MS")
    {
        set_env_var("GREENTIC_NETWORK_CONNECT_TIMEOUT_MS", &value);
        warnings.push(
            "OAUTH_CONNECT_TIMEOUT_MS is deprecated; set GREENTIC_NETWORK_CONNECT_TIMEOUT_MS instead"
                .into(),
        );
    }

    if std::env::var_os("GREENTIC_NETWORK_READ_TIMEOUT_MS").is_none()
        && let Ok(value) = std::env::var("OAUTH_REQUEST_TIMEOUT_MS")
    {
        set_env_var("GREENTIC_NETWORK_READ_TIMEOUT_MS", &value);
        warnings.push(
            "OAUTH_REQUEST_TIMEOUT_MS is deprecated; set GREENTIC_NETWORK_READ_TIMEOUT_MS instead"
                .into(),
        );
    }

    warnings
}

fn is_truthy_flag(value: &str) -> bool {
    ["1", "true", "yes", "on"]
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

fn set_env_var(name: &str, value: &str) {
    // SAFETY: Rust 2024 marks set_var as unsafe; here we scope it to known config aliasing.
    unsafe { std::env::set_var(name, value) };
}

fn print_plan_summary(value: &serde_json::Value) {
    let Some(teams) = value.get("teams").and_then(|v| v.as_array()) else {
        return;
    };
    if let Some(tenant) = value.get("tenant").and_then(|v| v.as_str()) {
        println!("Plan for tenant: {}", tenant);
    }
    for team in teams {
        let team_id = team
            .get("team_id")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        let action = team
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("none");
        println!("- team {}: {}", team_id, action);
        if let Some(subs) = team.get("subscriptions").and_then(|v| v.as_array()) {
            for sub in subs {
                let channel = sub
                    .get("channel_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<channel>");
                let sub_action = sub.get("action").and_then(|v| v.as_str()).unwrap_or("none");
                println!("    • channel {}: {}", channel, sub_action);
            }
        }
    }
    if let Some(warnings) = value.get("warnings").and_then(|v| v.as_array()) {
        for warning in warnings.iter().filter_map(|v| v.as_str()) {
            println!("  warning: {}", warning);
        }
    }
}
