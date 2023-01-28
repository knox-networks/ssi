use tracing_subscriber::{
    filter::LevelFilter, fmt, prelude::*, util::SubscriberInitExt, EnvFilter,
};

pub fn init_logger(level: &str) -> Result<(), tracing_subscriber::util::TryInitError> {
    println!("logger initialization");
    let level_filter = level
        .parse::<LevelFilter>()
        .expect("Level error can be parsed");
    let mut layers = Vec::new();
    let filter = EnvFilter::builder()
        .with_env_var("RUST_LOG")
        .with_default_directive(level_filter.into())
        .from_env_lossy();

    // Initialize stdout output;
    let stdout_layer = fmt::layer()
        .with_line_number(true)
        .with_file(true)
        .with_thread_ids(true)
        .with_target(true)
        .with_ansi(true);

    layers.push(stdout_layer.without_time().boxed());

    layers.push(tracing_error::ErrorLayer::default().boxed());

    tracing_subscriber::registry()
        .with(layers)
        .with(filter)
        .try_init()?;
    Ok(())
}
