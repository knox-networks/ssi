#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorKind {
    NotFound,
    InvalidData,
    Uncategorized,
    NetworkFailure,
}

#[derive(Debug, Clone)]
pub struct ResolverError {
    pub message: String,
    pub kind: ErrorKind,
}

impl std::fmt::Display for ResolverError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl ResolverError {
    pub fn new(message: impl Into<String>, kind: ErrorKind) -> Self {
        Self {
            message: message.into(),
            kind: kind,
        }
    }
}
