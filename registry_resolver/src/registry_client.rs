#[allow(non_snake_case, clippy::all, unused_imports, dead_code)]
#[rustfmt::skip]
#[path = "gen/registry_api.v1.rs"]
pub mod registry;

#[derive(Clone, Debug)]
pub struct GrpcClient {
    inner: registry::registry_service_client::RegistryServiceClient<tonic::transport::Channel>,
}

impl GrpcClient {
    pub async fn new(url: String) -> Self {
        let inner = registry::registry_service_client::RegistryServiceClient::connect(url.clone())
            .await
            .unwrap();
        Self { inner }
    }
}

#[async_trait::async_trait]
impl RegistryClient for GrpcClient {
    async fn create(
        &self,
        did: String,
        document: Option<pbjson_types::Struct>,
    ) -> Result<tonic::Response<registry::CreateResponse>, tonic::Status> {
        let mut client = self.inner.to_owned();

        return client
            .create(registry::CreateRequest { did, document })
            .await;
    }

    async fn read(
        &self,
        did: String,
    ) -> Result<tonic::Response<registry::ReadResponse>, tonic::Status> {
        let mut client = self.inner.to_owned();
        return client.read(registry::ReadRequest { did }).await;
    }
}

#[mockall::automock]
#[async_trait::async_trait]
pub trait RegistryClient: Send + Sync + std::fmt::Debug {
    async fn create(
        &self,
        did: String,
        document: Option<pbjson_types::Struct>,
    ) -> Result<tonic::Response<registry::CreateResponse>, tonic::Status>;

    async fn read(
        &self,
        did: String,
    ) -> Result<tonic::Response<registry::ReadResponse>, tonic::Status>;
}
