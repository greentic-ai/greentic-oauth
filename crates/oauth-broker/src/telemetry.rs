use greentic_telemetry::{set_context, CloudCtx};

pub fn set_request_context(
    tenant: Option<&str>,
    team: Option<&str>,
    flow: Option<&str>,
    run_id: Option<&str>,
) {
    set_context(CloudCtx {
        tenant,
        team,
        flow,
        run_id,
    });
}
