use std::num::TryFromIntError;

use chrono::TimeZone;

mod registry_client;
pub const DID_METHOD: &str = "knox";

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
        let client = registry_client::GrpcClient::new(url.into()).await;
        RegistryResolver { client }
    }
}

#[async_trait::async_trait]
impl<T> ssi_core::DIDResolver for RegistryResolver<T>
where
    T: registry_client::RegistryClient,
{
    fn get_method(&self) -> &'static str {
        get_method_helper()
    }

    async fn create(
        &self,
        did: String,
        document: serde_json::Value,
    ) -> Result<(), ssi_core::error::ResolverError> {
        self.client
            .create(did, document.to_string())
            .await
            .map_err(|e| ssi_core::error::ResolverError::NetworkFailure(e.to_string()))?;

        Ok(())
    }

    async fn resolve(
        &self,
        did: String,
    ) -> Result<ssi_core::ResolveResponse, ssi_core::error::ResolverError> {
        let res = self
            .client
            .resolve(did.clone())
            .await
            .map_err(|e| ssi_core::error::ResolverError::NetworkFailure(e.to_string()))?
            .into_inner();

        let document = res.did_document.ok_or({
            ssi_core::error::ResolverError::InvalidData(
                "No document found in registry response".to_string(),
            )
        })?;
        let document_metadata = res.did_document_metadata.ok_or({
            ssi_core::error::ResolverError::InvalidData(
                "No document metadata found in registry response".to_string(),
            )
        })?;

        let resolution_metadata = res.did_resolution_metadata.ok_or({
            ssi_core::error::ResolverError::InvalidData(
                "No resolution metadata found in registry response".to_string(),
            )
        })?;

        //timestamp to date
        let created = document_metadata.created.ok_or({
            ssi_core::error::ResolverError::InvalidData(
                "No created property found in document metadata in response".to_string(),
            )
        })?;
        let updated = document_metadata.updated.ok_or({
            ssi_core::error::ResolverError::InvalidData(
                "No updated property found in document metadata in response".to_string(),
            )
        })?;

        let created = chrono::Utc
            .timestamp_opt(
                created.seconds,
                created.nanos.try_into().map_err(|e: TryFromIntError| {
                    ssi_core::error::ResolverError::Unknown(e.to_string())
                })?,
            )
            .unwrap();

        let updated = chrono::Utc
            .timestamp_opt(
                updated.seconds,
                updated.nanos.try_into().map_err(|e: TryFromIntError| {
                    ssi_core::error::ResolverError::Unknown(e.to_string())
                })?,
            )
            .unwrap();

        let document_metadata = ssi_core::DidDocumentMetadata {
            created: created,
            updated: updated,
        };

        let did_url = resolution_metadata.did_url.ok_or({
            ssi_core::error::ResolverError::InvalidData(
                "No did url found in resolution metadata in response".to_string(),
            )
        })?;

        let resolution_metadata = ssi_core::ResolutionMetadata {
            duration: resolution_metadata.duration,
            error: resolution_metadata.error,
            content_type: resolution_metadata.content_type,
            did_url: Some(ssi_core::DidResolutionURL {
                did: did,
                method_specific_id: did_url.method_specific_id,
                method_name: did_url.method_name,
            }),
        };

        let document = serde_json::to_value(document).map_err(|e: serde_json::Error| {
            ssi_core::error::ResolverError::InvalidData(e.to_string())
        })?;

        Ok(ssi_core::ResolveResponse {
            did_document: document,
            did_document_metadata: document_metadata,
            did_resolution_metadata: Some(resolution_metadata),
        })
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        registry_client::{
            registry::ResolveResponse,
            registry::{CreateResponse, DidDocumentMetadata},
            MockRegistryClient,
        },
        RegistryResolver,
    };
    use ssi_core::DIDResolver;

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

    fn create_proto_did_doc(did: String) -> pbjson_types::Struct {
        let value = create_did_doc(did);

        serde_json::from_value(value).unwrap()
    }

    #[ignore = "registry contract test disabled"]
    #[tokio::test]
    async fn test_create_did_integration() {
        let did_doc = create_did();
        let address = "https://reg.sandbox5.knoxnetworks.io";
        let resolver = RegistryResolver::new(address.to_string()).await;
        let document_serialized = create_did_doc(did_doc.clone());
        let result = resolver
            .create(did_doc.to_string(), document_serialized)
            .await;
        assert!(result.is_ok())
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
        Some(Ok(tonic::Response::new(ResolveResponse {
            did_document: Some(create_proto_did_doc(create_did())),
            did_document_metadata: Some(DidDocumentMetadata{
                created: Some(pbjson_types::Timestamp{
                    seconds: 0,
                    nanos: 0
                }),
                updated: Some(pbjson_types::Timestamp{
                    seconds: 0,
                    nanos: 0
                })
            }),
            did_resolution_metadata: None
         }))),
        None,
        true
    )]
    fn test_read(
        #[case] did: String,
        #[case] mock_read_response: Option<Result<tonic::Response<ResolveResponse>, tonic::Status>>,
        #[case] expect_error_kind: Option<ssi_core::error::ResolverError>,
        #[case] expect_ok: bool,
    ) {
        let mut mock_client = MockRegistryClient::default();
        if let Some(res) = mock_read_response {
            mock_client
                .expect_resolve()
                .with(mockall::predicate::eq(did.clone()))
                .return_once(|_| res);
        }

        let resolver = RegistryResolver {
            client: mock_client,
        };

        let res = aw!(resolver.resolve(did));
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
        let mock_client = MockRegistryClient::default();

        let resolver = RegistryResolver {
            client: mock_client,
        };

        assert_eq!(resolver.get_method(), "knox");
        Ok(())
    }

    #[test]
    fn test_create_verification_method() -> Result<(), String> {
        let did = String::from("12345");
        let key_id = String::from("123456");
        let mock_client = MockRegistryClient::default();

        let resolver = RegistryResolver {
            client: mock_client,
        };

        assert_eq!(
            resolver.create_verification_method(did, key_id),
            "did:knox:12345#123456"
        );
        Ok(())
    }
}
