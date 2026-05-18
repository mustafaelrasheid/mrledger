use std::error::Error;
use std::fmt;
use std::string::FromUtf8Error;
use serde_json::error::Error as JsonError;

#[derive(Debug)]
pub enum InvalidInput {
    Utf8(FromUtf8Error),
    Json(JsonError),
    MissingData(String),
    FormatSupport(String),
}

impl Error for InvalidInput {}

impl fmt::Display for InvalidInput {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        return match self {
            InvalidInput::Utf8(err) =>{
                write!(formatter, "Invalid Utf8: {}", err)
            },
            InvalidInput::Json(err) => {
                write!(formatter, "Invalid json: {}", err)
            },
            InvalidInput::MissingData(err) => {
                write!(formatter, "Missing Data: {}", err)
            }
            InvalidInput::FormatSupport(err) => {
                write!(formatter, "Unsupported format: {}", err)
            },
        };
    }
}

