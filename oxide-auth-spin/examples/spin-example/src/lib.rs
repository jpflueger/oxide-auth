use anyhow::Result;
use spin_sdk::{
    http::{Request, Response},
    http_component,
};

/// A simple Spin HTTP component.
#[http_component]
fn handle_spin_example(req: Request) -> Result<Response> {
    println!("{:?}", req.headers());
    let body: String = oxide_auth_spin::WebError::Encoding.into();
    Ok(http::Response::builder()
        .status(200)
        .header("foo", "bar")
        .body(Some(body.into()))?)
}
