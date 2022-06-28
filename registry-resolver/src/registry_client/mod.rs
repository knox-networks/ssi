use mockall::*;
use registry::registry_service_client::RegistryServiceClient;

#[path = "../gen/registry_api.v1.rs"]
pub mod registry;

pub struct GrpcClient {
    inner: RegistryServiceClient<tonic::transport::Channel>,
}

#[automock]
impl GrpcClient {
    pub async fn new(url: String) -> Self {
        let inner = RegistryServiceClient::connect(url.clone())
            .await
            .unwrap()
            .to_owned();
        return Self { inner };
    }
    pub async fn create(
        self,
        did: String,
        document: Option<pbjson_types::Struct>,
    ) -> Result<tonic::Response<registry::CreateResponse>, tonic::Status> {
        let mut client = self.inner;

        return client
            .create(registry::CreateRequest { did, document })
            .await;
    }

    pub async fn read(
        self,
        did: String,
    ) -> Result<tonic::Response<registry::ReadResponse>, tonic::Status> {
        let mut client = self.inner;
        return client.read(registry::ReadRequest { did }).await;
    }
}
