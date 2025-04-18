//! Kernel TLS (kTLS) support for Rustls.

mod cipher;
mod error;
mod ffi;
pub mod setup;
mod stream;
pub mod utils;
mod version;

pub use cipher::{KtlsCipherSuite, KtlsCipherType};
pub use error::{CipherSuiteError, Error};
pub use ffi::CryptoInfo;
#[allow(deprecated)]
pub use setup::{config_ktls_client, config_ktls_server, Setup};
pub use stream::{cork::CorkStream, KtlsStream};
pub use utils::{
    async_read_ready::AsyncReadReady,
    compatible_ciphers::{CompatibleCiphers, CompatibleCiphersForVersion},
};
pub use version::KtlsVersion;
