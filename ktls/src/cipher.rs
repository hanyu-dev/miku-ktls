//! CipherSuite that kTLS utilize.

use rustls::SupportedCipherSuite;

use crate::{error::CipherSuiteError, version::KtlsVersion};

pub(crate) mod cipher_suite;

/// A TLS cipher suite. Used mostly internally.
#[derive(Clone, Copy)]
pub struct KtlsCipherSuite {
    /// The TLS version
    pub version: KtlsVersion,

    /// The cipher type
    pub typ: KtlsCipherType,
}

impl TryFrom<SupportedCipherSuite> for KtlsCipherSuite {
    type Error = CipherSuiteError;

    fn try_from(#[allow(unused)] suite: SupportedCipherSuite) -> Result<Self, Self::Error> {
        let version = match suite {
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(..) => KtlsVersion::TLS12,
            #[cfg(not(feature = "tls12"))]
            SupportedCipherSuite::Tls12(..) => {
                return Err(CipherSuiteError::Tls12NotBuiltIn);
            }
            SupportedCipherSuite::Tls13(..) => KtlsVersion::TLS13,
        };

        let typ = match suite {
            suite if suite == cipher_suite::TLS13_AES_128_GCM_SHA256 => KtlsCipherType::AesGcm128,
            suite if suite == cipher_suite::TLS13_AES_256_GCM_SHA384 => KtlsCipherType::AesGcm256,
            suite if suite == cipher_suite::TLS13_CHACHA20_POLY1305_SHA256 => {
                KtlsCipherType::Chacha20Poly1305
            }
            suite if suite == cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
                KtlsCipherType::AesGcm128
            }
            suite if suite == cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
                KtlsCipherType::AesGcm256
            }
            suite if suite == cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
                KtlsCipherType::Chacha20Poly1305
            }
            _ => return Err(CipherSuiteError::UnsupportedCipherSuite(suite)),
        };

        Ok(Self { version, typ })
    }
}

impl KtlsCipherSuite {
    #[inline]
    /// Converts this cipher suite into the equivalent `rustls`
    /// [`SupportedCipherSuite`].
    pub const fn as_supported_cipher_suite(&self) -> SupportedCipherSuite {
        match self.version {
            KtlsVersion::TLS12 => match self.typ {
                KtlsCipherType::AesGcm128 => cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                KtlsCipherType::AesGcm256 => cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                KtlsCipherType::Chacha20Poly1305 => {
                    cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                }
            },
            KtlsVersion::TLS13 => match self.typ {
                KtlsCipherType::AesGcm128 => cipher_suite::TLS13_AES_128_GCM_SHA256,
                KtlsCipherType::AesGcm256 => cipher_suite::TLS13_AES_256_GCM_SHA384,
                KtlsCipherType::Chacha20Poly1305 => cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            },
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
/// Cipher types supported by this crate
pub enum KtlsCipherType {
    AesGcm128,
    AesGcm256,
    Chacha20Poly1305,
}
