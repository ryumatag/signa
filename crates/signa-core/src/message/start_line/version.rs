use std::fmt;

/// A SIP protocol version.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Version(Sip);

impl Version {
    /// The standardized SIP/2.0 version token.
    pub const SIP_2_0: Version = Version(Sip::Sip2_0);

    /// Returns the canonical SIP version as a string slice.
    pub const fn as_str(&self) -> &str {
        match self.0 {
            Sip::Sip2_0 => "SIP/2.0",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Sip {
    Sip2_0,
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Default for Version {
    fn default() -> Version {
        Version::SIP_2_0
    }
}

#[cfg(test)]
mod tests {
    use super::Version;

    #[test]
    fn as_str_returns_canonical_sip_version() {
        assert_eq!(Version::SIP_2_0.as_str(), "SIP/2.0");
    }

    #[test]
    fn debug() {
        assert_eq!(format!("{:?}", Version::SIP_2_0), "SIP/2.0");
    }

    #[test]
    fn display() {
        assert_eq!(format!("{}", Version::SIP_2_0), "SIP/2.0");
    }
}
