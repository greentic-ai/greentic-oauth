use clap::{Parser, Subcommand};
use greentic_config::ConfigResolver;
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let legacy_warnings = apply_legacy_env_aliases();
    let resolved = ConfigResolver::new()
        .with_cli_overrides(greentic_config::CliOverrides {
            config_path: cli.config.clone(),
            ..Default::default()
        })
        .load()?;

    if cli.explain_config {
        println!("{}", resolved.explain());
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
    let aliases = [
        ("OAUTH_HTTP_PROXY", "GREENTIC_PROXY"),
        ("OAUTH_NO_PROXY", "GREENTIC_NO_PROXY"),
        ("OAUTH_TLS_INSECURE", "GREENTIC_TLS_INSECURE"),
        ("OAUTH_CONNECT_TIMEOUT_MS", "GREENTIC_CONNECT_TIMEOUT_MS"),
        ("OAUTH_REQUEST_TIMEOUT_MS", "GREENTIC_NETWORK_TIMEOUT_MS"),
        ("ALLOW_INSECURE", "GREENTIC_TLS_INSECURE"),
    ];

    for (legacy, target) in aliases {
        if std::env::var_os(target).is_none()
            && let Ok(value) = std::env::var(legacy)
        {
            // SAFETY: scoped aliasing of known env vars
            unsafe { std::env::set_var(target, value) };
            warnings.push(format!(
                "{legacy} is deprecated; set {target} or greentic-config files instead"
            ));
        }
    }

    warnings
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
