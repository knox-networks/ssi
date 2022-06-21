pub mod registry {
    tonic::include_proto!("registry_api.v1");
}

pub struct RegistryResolver {}

impl ssi::DIDResolver for RegistryResolver {
    fn create(&self, _did: &str, _doc: serde_json::Value) -> String {
        return String::from("");
    }

    fn read(&self, _did: &str) -> serde_json::Value {
        return serde_json::json!("{}");
    }
}
