pub mod registry {
    include!(concat!(env!("OUT_DIR"), "/gen/registry_api.v1.rs"));
}

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
        document: String,
    ) -> Result<tonic::Response<registry::CreateResponse>, tonic::Status> {
        let mut client = self.inner.to_owned();

        return client
            .create(registry::CreateRequest { did, document })
            .await;
    }

    async fn resolve(
        &self,
        did: String,
    ) -> Result<tonic::Response<registry::ResolveResponse>, tonic::Status> {
        let mut client = self.inner.to_owned();
        return client
            .resolve(registry::ResolveRequest {
                did,
                resolution_option: None,
            })
            .await;
    }
}

#[mockall::automock]
#[async_trait::async_trait]
pub trait RegistryClient: Send + Sync + std::fmt::Debug {
    async fn create(
        &self,
        did: String,
        document: String,
    ) -> Result<tonic::Response<registry::CreateResponse>, tonic::Status>;

    async fn resolve(
        &self,
        did: String,
    ) -> Result<tonic::Response<registry::ResolveResponse>, tonic::Status>;
}

impl Clone for MockRegistryClient {
    fn clone(&self) -> Self {
        Self::default()
    }
}
