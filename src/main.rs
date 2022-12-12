use zero_axum::{
    configuration::get_configuration,
    startup::Application,
    telemetry::{get_subscriber, init_subscriber},
};

#[tokio::main]
async fn main() -> hyper::Result<()> {
    let subscriber = get_subscriber("zero_axum".into(), "info".into(), std::io::stdout);
    init_subscriber(subscriber);

    let configuration = get_configuration().expect("Failed to read configuration");

    let app = Application::build(configuration).expect("Failed to build application");

    app.run_until_stopped().await
}
