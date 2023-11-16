use sophia::{
    api::{parser::QuadParser, source::QuadSource},
    c14n::hash::HashFunction,
    inmem::dataset::FastDataset,
    jsonld::loader::HttpLoader,
};

pub fn create_hashed_normalized_doc(
    doc: serde_json::Value,
) -> Result<[u8; 32], crate::error::Error> {
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
        crate::error::Error::Unknown(format!("Error normalizing JSON-LD dataset: {}", e))
    })?;

    let mut hasher = sophia::c14n::hash::Sha256::initialize();
    hasher.update(&output);

    Ok(hasher.finalize())
}
