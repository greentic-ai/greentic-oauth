use greentic_telemetry::dev;

#[test]
fn info_log_snapshot() {
    dev::test_init_for_snapshot().expect("snapshot init");

    let logs = dev::capture_logs(|| {
        tracing::info!(tenant = "demo-tenant", user_id = "007", "snapshot log");
    });

    let snapshot = logs.join("\n");
    insta::assert_snapshot!("info_log", snapshot);
}
