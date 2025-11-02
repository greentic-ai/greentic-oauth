use super::manifest::{ManifestContext, ProviderCatalog, ResolvedProviderManifest};

pub const PROVIDER_ID: &str = "oidc-generic";

pub fn resolve_manifest<'a>(
    catalog: &'a ProviderCatalog,
    tenant: &'a str,
    team: Option<&'a str>,
    user: Option<&'a str>,
) -> Option<ResolvedProviderManifest> {
    let ctx = ManifestContext::new(tenant, PROVIDER_ID, team, user);
    catalog.resolve(PROVIDER_ID, &ctx)
}
