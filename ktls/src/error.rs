//! Crate error type

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to enable TLS ULP (upper level protocol): {0}")]
    UlpError(#[source] std::io::Error),

    #[error("kTLS compatibility error: {0}")]
    KtlsCompatibility(#[from] crate::ffi::KtlsCompatibilityError),

    #[error("failed to export secrets")]
    ExportSecrets(#[source] rustls::Error),

    #[error("failed to configure tx/rx (unsupported cipher?): {0}")]
    TlsCryptoInfoError(#[source] std::io::Error),

    #[error("an I/O occured while draining the rustls stream: {0}")]
    DrainError(#[source] std::io::Error),

    #[error("no negotiated cipher suite: call config_ktls_* only /after/ the handshake")]
    NoNegotiatedCipherSuite,

    #[error("reuse after kTLS has been successfully setup")]
    ReuseAfterKtlsSetup,
}
