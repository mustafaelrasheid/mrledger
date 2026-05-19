use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum InvalidInput {
    MissingData(String),
}

impl Error for InvalidInput {}

impl fmt::Display for InvalidInput {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        return match self {
            InvalidInput::MissingData(err) => {
                write!(formatter, "Missing Data: {}", err)
            }
        };
    }
}

