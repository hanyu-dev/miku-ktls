//! kTLS Version

use rustls::SupportedProtocolVersion;

#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
/// TLS versions supported by this crate.
pub enum KtlsVersion {
    TLS12,
    TLS13,
}

impl KtlsVersion {
    #[inline]
    /// Converts into the equivalent `rustls` [`SupportedProtocolVersion`].
    pub const fn as_supported_version(&self) -> &'static SupportedProtocolVersion {
        match self {
            Self::TLS12 => &rustls::version::TLS12,
            Self::TLS13 => &rustls::version::TLS13,
        }
    }
}
