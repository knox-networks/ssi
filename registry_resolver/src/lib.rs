mod registry_client;
const DID_METHOD: &str = "knox";

#[derive(Clone, Debug)]
pub struct RegistryResolver<T = registry_client::GrpcClient>
where
    T: registry_client::RegistryClient + 'static,
{
    client: T,
}

const fn get_method_helper() -> &'static str {
    DID_METHOD
}

impl RegistryResolver<registry_client::GrpcClient> {
    pub async fn new(url: impl Into<String>) -> Self {
        println!("<<<<<<<<<<------------------------------->>>>>>>>>>>>  Connecting to registry resolver at {}", url.into());
        let client = registry_client::GrpcClient::new("https://reg.knoxnetworks.io:5051".to_string()).await;
        RegistryResolver { client }
    }
}
#[async_trait::async_trait]
impl<T> ssi_core::DIDResolver for RegistryResolver<T>
where
    T: registry_client::RegistryClient,
{
    fn get_method() -> &'static str {
        get_method_helper()
    }

    async fn create(
        self,
        did: String,
        document: serde_json::Value,
    ) -> Result<(), ssi_core::error::ResolverError> {
        self.client
            .create(did, document.to_string())
            .await
            .map_err(|e| ssi_core::error::ResolverError::NetworkFailure(e.to_string()))?;

        Ok(())
    }

    async fn read(self, did: String) -> Result<serde_json::Value, ssi_core::error::ResolverError> {
        let res = self
            .client
            .read(did.clone())
            .await
            .map_err(|e| ssi_core::error::ResolverError::NetworkFailure(e.to_string()))?;

        let document = res.into_inner().document;

        Ok(serde_json::from_str(&document)
            .map_err(|e| ssi_core::error::ResolverError::InvalidData(e.to_string()))?)
    }
}

#[cfg(test)]
mod tests {
    use ssi_core::DIDResolver;

    use crate::{
        registry_client::{
            registry::CreateResponse, registry::ReadResponse, GrpcClient, MockRegistryClient,
        },
        RegistryResolver,
    };

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    fn create_did_doc(did: String) -> serde_json::Value {
        serde_json::json!({
                "@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/ed25519-2020/v1"],
                "id":did,
                "authentication":[
                    {"id":format!("did:knox:{}#{}", did, did),"type":"Ed25519VerificationKey2020","controller":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh","publicKeyMultibase":"z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh"
                }],
                "capabilityInvocation":[
                    {"id":format!("did:knox:{}#{}", did, did),"type":"Ed25519VerificationKey2020","controller":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh","publicKeyMultibase":"z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh"
                }],
                "capabilityDelegation":[
                    {"id":format!("did:knox:{}#{}", did, did),"type":"Ed25519VerificationKey2020","controller":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh","publicKeyMultibase":"z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh"
                }],
                "assertionMethod":[
                    {"id":format!("did:knox:{}#{}", did, did),"type":"Ed25519VerificationKey2020","controller":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh","publicKeyMultibase":"z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh"
                }]
            }
        )
    }

    fn create_did() -> String {
        String::from("did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh")
    }

    #[rstest::rstest]
    #[case::network_failure(
        create_did(),
        create_did_doc(create_did()),
        Some(Err(tonic::Status::invalid_argument("message"))),
        Some(ssi_core::error::ResolverError::NetworkFailure(r#"status: InvalidArgument, message: "message", details: [], metadata: MetadataMap { headers: {} }"#.to_string())),
        false
    )]
    #[case::success(
        create_did(),
        create_did_doc(create_did()),
        Some(Ok(tonic::Response::new(CreateResponse {}))),
        None,
        true
    )]
    fn test_create(
        #[case] did: String,
        #[case] doc: serde_json::Value,
        #[case] mock_create_response: Option<
            Result<tonic::Response<CreateResponse>, tonic::Status>,
        >,
        #[case] expect_error_kind: Option<ssi_core::error::ResolverError>,
        #[case] expect_ok: bool,
    ) {
        let mut mock_client = MockRegistryClient::default();
        if let Some(res) = mock_create_response {
            mock_client
                .expect_create()
                .with(
                    mockall::predicate::eq(did.clone()),
                    mockall::predicate::eq(doc.to_string()),
                )
                .return_once(|_, _| (res));
        }

        let resolver = RegistryResolver {
            client: mock_client,
        };

        let res = aw!(resolver.create(did, doc));
        assert_eq!(res.is_ok(), expect_ok);
        match res.err() {
            Some(e) => {
                assert_eq!(e, expect_error_kind.unwrap());
            }
            None => assert!(expect_error_kind.is_none()),
        }
    }

    #[rstest::rstest]
    #[case::network_failure(
        create_did(),
        Some(Err(tonic::Status::invalid_argument("message"))),
        Some(ssi_core::error::ResolverError::NetworkFailure(r#"status: InvalidArgument, message: "message", details: [], metadata: MetadataMap { headers: {} }"#.to_string())),
        false
    )]
    #[case::success(
        create_did(),
        Some(Ok(tonic::Response::new(ReadResponse {
            did: create_did(),
            document: create_did_doc(create_did()).to_string(),
            metadata: None,
         }))),
        None,
        true
    )]
    fn test_read(
        #[case] did: String,
        #[case] mock_read_response: Option<Result<tonic::Response<ReadResponse>, tonic::Status>>,
        #[case] expect_error_kind: Option<ssi_core::error::ResolverError>,
        #[case] expect_ok: bool,
    ) {
        let mut mock_client = MockRegistryClient::default();
        if let Some(res) = mock_read_response {
            mock_client
                .expect_read()
                .with(mockall::predicate::eq(did.clone()))
                .return_once(|_| res);
        }

        let resolver = RegistryResolver {
            client: mock_client,
        };

        let res = aw!(resolver.read(did));
        assert_eq!(res.is_ok(), expect_ok);
        match res.err() {
            Some(e) => {
                assert_eq!(e, expect_error_kind.unwrap());
            }
            None => assert!(expect_error_kind.is_none()),
        }
    }

    #[test]
    fn test_get_method() -> Result<(), String> {
        assert_eq!(RegistryResolver::<GrpcClient>::get_method(), "knox");
        Ok(())
    }

    #[test]
    fn test_create_verification_method() -> Result<(), String> {
        let did = String::from("12345");
        let key_id = String::from("123456");
        assert_eq!(
            RegistryResolver::<GrpcClient>::create_verification_method(did, key_id),
            "did:knox:12345#123456"
        );
        Ok(())
    }
}
