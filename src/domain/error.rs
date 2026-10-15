use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Usage(String),
    Config(String),
    Unsupported(String),
    Verification(String),
    Approval(String),
    Io(String),
    PostLaunch(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Usage(_) | Error::Config(_) => 2,
            Error::Unsupported(_) => 3,
            Error::Verification(_) => 4,
            Error::Approval(_) => 5,
            Error::Io(_) => 1,
            Error::PostLaunch(_) => 70,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usage(m)
            | Error::Config(m)
            | Error::Unsupported(m)
            | Error::Verification(m)
            | Error::Approval(m)
            | Error::Io(m)
            | Error::PostLaunch(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_design() {
        assert_eq!(Error::Usage(String::new()).exit_code(), 2);
        assert_eq!(Error::Unsupported(String::new()).exit_code(), 3);
        assert_eq!(Error::Verification(String::new()).exit_code(), 4);
        assert_eq!(Error::Approval(String::new()).exit_code(), 5);
        assert_eq!(Error::PostLaunch(String::new()).exit_code(), 70);
    }
}
