use sophia::{api::source::QuadSource, c14n::hash::HashFunction, inmem::dataset::FastDataset};

pub fn normalize(doc: serde_json::Value) -> [u8; 32] {
    let encoded = doc.to_string();
    println!("{encoded}");
    let mut dataset = FastDataset::new();
    sophia::jsonld::parse_str(&encoded)
        .add_to_dataset(&mut dataset)
        .unwrap();
    println!("dataset {:?}", dataset);

    let mut output = Vec::<u8>::new();
    sophia::c14n::rdfc10::normalize(&dataset, &mut output).unwrap();
    println!("output {:?}, length: {:?}", output, output.len());

    let mut hasher = sophia::c14n::hash::Sha256::initialize();
    hasher.update(&output);

    hasher.finalize()
}
