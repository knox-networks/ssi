// Context must contain at least one URI
// The first URI must be https://www.w3.org/2018/credentials/v1 (use BASE_CREDENDIAL_CONTEXT)
pub fn credential_context_validation(
    val: &Vec<String>,
) -> Result<(), serde_valid::validation::Error> {
    if val.len() == 0 {
        return Err(serde_valid::validation::Error::Custom(
            "Context must contain at least one URI".to_string(),
        ));
    }

    if val[0] != super::BANK_ACCOUNT_CREDENTIAL_CONTEXT {
        return Err(serde_valid::validation::Error::Custom(format!(
            "The first URI must be {}",
            super::BANK_ACCOUNT_CREDENTIAL_CONTEXT,
        )));
    }

    Ok(())
}
