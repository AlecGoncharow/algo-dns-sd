use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("")]
    NotEnoughBytes(usize, usize),
    #[error("")]
    UnsupportedValue { value: String, kind: String },
}
