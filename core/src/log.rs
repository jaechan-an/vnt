use std::path::Path;
use tracing_appender::rolling;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::layer;
use tracing_subscriber::{Layer, Registry};

pub fn create_log_layer(
    logdir: &String,
    logfile: &String,
    logfilter: LevelFilter,
) -> Box<dyn Layer<Registry> + Send + Sync> {
    let _logdir = Path::new(".").join(&logdir);
    std::fs::create_dir_all(&_logdir).expect("Failed to create log directory");

    let file_appender = rolling::daily(_logdir, logfile);
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let debug_logs = layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .compact()
        .with_filter(logfilter);

    Box::new(debug_logs)
}

// Function to convert user input into LevelFilter
pub fn get_log_level(level: &str) -> LevelFilter {
    match level.to_uppercase().as_str() {
        "TRACE" => LevelFilter::TRACE,
        "DEBUG" => LevelFilter::DEBUG,
        "INFO" => LevelFilter::INFO,
        "WARN" => LevelFilter::WARN,
        "ERROR" => LevelFilter::ERROR,
        _ => LevelFilter::INFO, // Default to INFO if invalid input
    }
}
