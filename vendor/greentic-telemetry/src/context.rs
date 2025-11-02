use crate::init::TELEMETRY_STATE;

pub struct CloudCtx<'a> {
    pub tenant: Option<&'a str>,
    pub team: Option<&'a str>,
    pub flow: Option<&'a str>,
    pub run_id: Option<&'a str>,
}

impl<'a> CloudCtx<'a> {
    pub fn empty() -> Self {
        Self {
            tenant: None,
            team: None,
            flow: None,
            run_id: None,
        }
    }
}

pub fn set_context(ctx: CloudCtx<'_>) {
    if let Some(state) = TELEMETRY_STATE.get() {
        state.set_context_value("tenant", ctx.tenant);
        state.set_context_value("team", ctx.team);
        state.set_context_value("flow", ctx.flow);
        state.set_context_value("run_id", ctx.run_id);
    }
}
