use super::ContextValue;

// Context must contain at least one URI
// The first URI must be https://www.w3.org/2018/credentials/v1 (use BASE_CREDENDIAL_CONTEXT)
pub fn credential_context_validation(
    val: &[ContextValue],
) -> Result<(), serde_valid::validation::Error> {
    match val.get(0) {
        None => {
            // Context must contain at least one URI
            Err(serde_valid::validation::Error::Custom(
                "Context must contain at least one URI".to_string(),
            ))
        }
        Some(ContextValue::String(ref s))
            if s != super::BASE_CREDENTIAL_CONTEXT && s != super::BASE_CREDENTIAL_CONTEXT_V2 =>
        {
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

#[cfg(test)]
mod tests {
    use super::super::BASE_CREDENTIAL_CONTEXT;
    use super::ContextValue;

    #[rstest::rstest]
    #[case::empty_context(
        vec![],
        Err(serde_valid::validation::Error::Custom(
            "Context must contain at least one URI".to_string()
        ))
    )]
    #[case::first_uri_not_base(
        vec![super::ContextValue::String("https://www.w3.org/2018/credentials/v2".to_string())],
        Err(serde_valid::validation::Error::Custom(
            "The first URI must be https://www.w3.org/2018/credentials/v1, instead found https://www.w3.org/2018/credentials/v2".to_string()
        ))
    )]
    #[case::first_uri_not_string(
        vec![super::ContextValue::Object(std::collections::HashMap::new())],
        Err(serde_valid::validation::Error::Custom(
            "The first URI must be a string".to_string()
        ))
    )]
    #[case::valid_context(
        vec![super::ContextValue::String(BASE_CREDENTIAL_CONTEXT.to_string())],
        Ok(())
    )]
    fn test_validate_credential_context(
        #[case] context: Vec<super::ContextValue>,
        #[case] expected: Result<(), serde_valid::validation::Error>,
    ) {
        match super::credential_context_validation(&context) {
            Ok(_) => assert!(expected.is_ok()),
            Err(e) => assert_eq!(e.to_string(), expected.unwrap_err().to_string()),
        }
    }
}
