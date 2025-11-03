use greentic_telemetry::{CloudCtx, set_context};

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
