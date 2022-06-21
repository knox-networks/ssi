// #[path = "../target/proto/registry_api.v1.rs"]
// #[allow(clippy::all)]
// #[rustfmt::skip]
// pub mod registry;
pub mod registry {
    tonic::include_proto!("registry_api.v1");
}

pub fn create() {
    println!("Hello")
}
