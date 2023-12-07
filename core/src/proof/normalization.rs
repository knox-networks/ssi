use sophia::{
    api::{parser::QuadParser, source::QuadSource},
    c14n::hash::HashFunction,
    inmem::dataset::FastDataset,
    jsonld::loader::HttpLoader,
};

/**
 * This function is used to create a normalized document from a JSON-LD document.
 * It uses the RDFC10 normalization algorithm. As is required by Ed25519Signature2020 and `eddsa-rdfc-2022`.
 * It is essentially a very slightly modified version of URDNA2015.
 */
pub fn create_normalized_doc(doc: serde_json::Value) -> Result<Vec<u8>, crate::error::Error> {
    let encoded = doc.to_string();
    let mut dataset = FastDataset::new();
    let loader = sophia::jsonld::loader::HttpLoader::default();
    let options = sophia::jsonld::JsonLdOptions::<HttpLoader>::default();
    let parser = sophia::jsonld::parser::JsonLdParser::new_with_options(
        options.with_document_loader(loader),
    );
    parser
        .parse_str(&encoded)
        .add_to_dataset(&mut dataset)
        .map_err(|e| {
            crate::error::Error::Unknown(format!("Error parsing JSON-LD document: {}", e))
        })?;

    let mut output = Vec::<u8>::new();
    sophia::c14n::rdfc10::normalize(&dataset, &mut output).map_err(|e| {
        crate::error::Error::Unknown(format!("Error normalizing JSON-LD dataset1: {}", e))
    })?;

    Ok(output)
}

pub fn hash(data: &[u8]) -> Result<[u8; 32], crate::error::Error> {
    let mut hasher = sophia::c14n::hash::Sha256::initialize();
    hasher.update(data);
    let hash_data = hasher.finalize();
    Ok(hash_data)
}
