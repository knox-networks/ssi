use super::ContextValue;

// Context must contain at least one URI
// The first URI must be https://www.w3.org/2018/credentials/v1 (use BASE_CREDENDIAL_CONTEXT)
pub fn credential_context_validation(
    val: &Vec<ContextValue>,
) -> Result<(), serde_valid::validation::Error> {
    match val.get(0) {
        None => {
            // Context must contain at least one URI
            Err(serde_valid::validation::Error::Custom(
                "Context must contain at least one URI".to_string(),
            ))
        }
        Some(ContextValue::String(ref s)) if s != super::BASE_CREDENTIAL_CONTEXT => {
            Err(serde_valid::validation::Error::Custom(format!(
                "The first URI must be {}, instead found {}",
                super::BASE_CREDENTIAL_CONTEXT,
                s
            )))
        }
        Some(ContextValue::Object(_)) => Err(serde_valid::validation::Error::Custom(
            "The first URI must be a string".to_string(),
        )),
        _ => Ok(()),
    }
}
