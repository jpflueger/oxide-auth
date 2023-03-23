/// Something went wrong with the rouille http request or response.
#[derive(Debug)]
pub enum WebError {
    /// A parameter was encoded incorrectly.
    ///
    /// This may happen for example due to a query parameter that is not valid utf8 when the query
    /// parameters are necessary for OAuth processing.
    Encoding,
}

impl Into<String> for WebError {
    fn into(self) -> String {
        match self {
            WebError::Encoding => "WebError::Encoding".into(),
        }
    }
}
