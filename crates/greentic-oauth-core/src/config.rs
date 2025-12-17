use greentic_config_types::{NetworkConfig, TelemetryConfig, TlsMode};
use reqwest::blocking::{Client as BlockingClient, ClientBuilder as BlockingClientBuilder};
use reqwest::{Client, ClientBuilder, Proxy};
use std::time::Duration;

/// Runtime options derived from GreenticConfig and injected into OAuth clients.
#[derive(Clone, Debug, Default)]
pub struct OAuthClientOptions {
    pub network: NetworkConfig,
    pub telemetry: TelemetryConfig,
}

impl OAuthClientOptions {
    /// Create options from discrete config pieces.
    pub fn new(network: NetworkConfig, telemetry: TelemetryConfig) -> Self {
        Self { network, telemetry }
    }

    /// Build a reqwest client honoring the configured network policy (proxy, TLS mode, timeouts).
    pub fn build_http_client(&self) -> Result<Client, reqwest::Error> {
        let builder = ClientBuilder::new();
        self.apply_network(builder).build()
    }

    /// Build a blocking reqwest client honoring the configured network policy.
    pub fn build_blocking_http_client(&self) -> Result<BlockingClient, reqwest::Error> {
        let builder = BlockingClientBuilder::new();
        self.apply_network(builder).build()
    }

    fn apply_network<B>(&self, mut builder: B) -> B
    where
        B: ProxyConfigurable + TimeoutConfigurable + TlsConfigurable,
    {
        if let Some(proxy) = self.network.proxy_url.as_ref()
            && let Ok(proxy_cfg) = Proxy::all(proxy)
        {
            builder = builder.with_proxy(proxy_cfg);
        }

        if let Some(connect_ms) = self.network.connect_timeout_ms {
            builder = builder.with_connect_timeout(Duration::from_millis(connect_ms));
        }
        if let Some(read_ms) = self.network.read_timeout_ms {
            builder = builder.with_timeout(Duration::from_millis(read_ms));
        }

        if matches!(self.network.tls_mode, TlsMode::Disabled) {
            builder = builder.with_insecure_tls();
        }

        builder
    }
}

trait ProxyConfigurable: Sized {
    fn with_proxy(self, proxy: Proxy) -> Self;
}

trait TimeoutConfigurable: Sized {
    fn with_connect_timeout(self, timeout: Duration) -> Self;
    fn with_timeout(self, timeout: Duration) -> Self;
}

trait TlsConfigurable: Sized {
    fn with_insecure_tls(self) -> Self;
}

impl ProxyConfigurable for ClientBuilder {
    fn with_proxy(self, proxy: Proxy) -> Self {
        self.proxy(proxy)
    }
}

impl ProxyConfigurable for BlockingClientBuilder {
    fn with_proxy(self, proxy: Proxy) -> Self {
        self.proxy(proxy)
    }
}

impl TimeoutConfigurable for ClientBuilder {
    fn with_connect_timeout(self, timeout: Duration) -> Self {
        self.connect_timeout(timeout)
    }

    fn with_timeout(self, timeout: Duration) -> Self {
        self.timeout(timeout)
    }
}

impl TimeoutConfigurable for BlockingClientBuilder {
    fn with_connect_timeout(self, timeout: Duration) -> Self {
        self.connect_timeout(timeout)
    }

    fn with_timeout(self, timeout: Duration) -> Self {
        self.timeout(timeout)
    }
}

impl TlsConfigurable for ClientBuilder {
    fn with_insecure_tls(self) -> Self {
        self.danger_accept_invalid_certs(true)
    }
}

impl TlsConfigurable for BlockingClientBuilder {
    fn with_insecure_tls(self) -> Self {
        self.danger_accept_invalid_certs(true)
    }
}
