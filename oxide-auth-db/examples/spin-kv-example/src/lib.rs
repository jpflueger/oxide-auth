use anyhow::Result;
use oxide_auth::{frontends::simple::endpoint::Generic, primitives::prelude::RandomGenerator};
use oxide_auth_db::{db_service::spin_kv::{SpinKeyValueDataSource, SpinKeyValueAuthorizer}, primitives::db_registrar::DBRegistrar};
use spin_sdk::{
    http::{Request, Response},
    http_component,
};

/// A simple Spin HTTP component.
#[http_component]
fn handle_spin_kv_example(req: Request) -> Result<Response> {
    println!("{:?}", req.headers());

    let registrar_store_name = "registrars";
    let authorizer_store_name = "authorizers";

    let registrar_data_source = SpinKeyValueDataSource::new(registrar_store_name)?;

    let authorizer_tagger = RandomGenerator::new(16);

    
    let endpoint = Generic {
        registrar: DBRegistrar::new(Box::from(registrar_data_source), None),
        authorizer: SpinKeyValueAuthorizer::new(authorizer_store_name, authorizer_tagger)?,
    };

    Ok(http::Response::builder()
        .status(200)
        .header("foo", "bar")
        .body(Some("Hello, Fermyon".into()))?)
}
