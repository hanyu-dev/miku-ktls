//! kTLS compatible ciphers checker.

use std::{future::Future, io, net::SocketAddr, os::unix::io::AsRawFd};

use rustls::SupportedCipherSuite;
use smallvec::SmallVec;
use tokio::net::{TcpListener, TcpStream};

use crate::{
    cipher::{cipher_suite, KtlsCipherSuite, KtlsCipherType},
    version::KtlsVersion,
    CryptoInfo, Error,
};

#[derive(Debug, Default, Clone, Copy)]
/// kTLS compatible ciphers.
pub struct CompatibleCiphers {
    /// TLS 1.2 compatible ciphers.
    pub tls12: CompatibleCiphersForVersion,

    /// TLS 1.3 compatible ciphers.
    pub tls13: CompatibleCiphersForVersion,
}

impl CompatibleCiphers {
    /// List compatible ciphers. This listens on a TCP socket and blocks for a
    /// little while. Do once at the very start of a program.
    pub async fn new() -> io::Result<Self> {
        let mut ciphers = CompatibleCiphers::default();

        let ln = TcpListener::bind("0.0.0.0:0").await?;
        let local_addr = ln.local_addr()?;

        // Accepted conns of ln
        let mut accepted_conns: SmallVec<[TcpStream; 12]> = SmallVec::new();

        let accept_conns_fut = async {
            loop {
                if let Ok((conn, _addr)) = ln.accept().await {
                    accepted_conns.push(conn);
                }
            }
        };

        ciphers.test_ciphers(local_addr, accept_conns_fut).await?;

        Ok(ciphers)
    }

    async fn test_ciphers(
        &mut self,
        local_addr: SocketAddr,
        accept_conns_fut: impl Future<Output = ()>,
    ) -> io::Result<()> {
        let ciphers: Vec<(SupportedCipherSuite, &mut bool)> = vec![
            (
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                &mut self.tls13.aes_gcm_128,
            ),
            (
                cipher_suite::TLS13_AES_256_GCM_SHA384,
                &mut self.tls13.aes_gcm_256,
            ),
            (
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                &mut self.tls13.chacha20_poly1305,
            ),
            (
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                &mut self.tls12.aes_gcm_128,
            ),
            (
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                &mut self.tls12.aes_gcm_256,
            ),
            (
                cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                &mut self.tls12.chacha20_poly1305,
            ),
        ];

        let create_connections_fut = futures_util::future::try_join_all(
            (0..ciphers.len()).map(|_| TcpStream::connect(local_addr)),
        );

        let socks = tokio::select! {
            // Use biased here to optimize performance.
            //
            // With biased, tokio::select! would first poll create_connections_fut,
            // which would poll all `TcpStream::connect` futures and requests
            // new connections to `ln` then returns `Poll::Pending`.
            //
            // Then accept_conns_fut would be polled, which accepts all pending
            // connections, wake up create_connections_fut then returns
            // `Poll::Pending`.
            //
            // Finally, create_connections_fut wakes up and all connections
            // are ready, the result is collected into a Vec and ends
            // the tokio::select!.
            biased;

            res = create_connections_fut => res?,
            _ = accept_conns_fut => unreachable!(),
        };

        assert_eq!(ciphers.len(), socks.len());

        ciphers
            .into_iter()
            .zip(socks)
            .for_each(|((cipher_suite, field), sock)| {
                *field = sample_cipher_setup(&sock, cipher_suite).is_ok();
            });

        Ok(())
    }

    /// Returns true if we're reasonably confident that functions like
    /// [config_ktls_client] and [config_ktls_server] will succeed.
    pub fn is_compatible(&self, suite: SupportedCipherSuite) -> bool {
        let kcs = match KtlsCipherSuite::try_from(suite) {
            Ok(kcs) => kcs,
            Err(_) => return false,
        };

        let fields = match kcs.version {
            KtlsVersion::TLS12 => &self.tls12,
            KtlsVersion::TLS13 => &self.tls13,
        };

        match kcs.typ {
            KtlsCipherType::AesGcm128 => fields.aes_gcm_128,
            KtlsCipherType::AesGcm256 => fields.aes_gcm_256,
            KtlsCipherType::Chacha20Poly1305 => fields.chacha20_poly1305,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CompatibleCiphersForVersion {
    pub aes_gcm_128: bool,
    pub aes_gcm_256: bool,
    pub chacha20_poly1305: bool,
}

fn sample_cipher_setup(sock: &TcpStream, cipher_suite: SupportedCipherSuite) -> Result<(), Error> {
    let kcs = match KtlsCipherSuite::try_from(cipher_suite) {
        Ok(kcs) => kcs,
        Err(_) => panic!("unsupported cipher suite"),
    };

    let ffi_version = match kcs.version {
        KtlsVersion::TLS12 => crate::ffi::TLS_1_2_VERSION_NUMBER,
        KtlsVersion::TLS13 => crate::ffi::TLS_1_3_VERSION_NUMBER,
    };

    let crypto_info = match kcs.typ {
        KtlsCipherType::AesGcm128 => {
            CryptoInfo::AesGcm128(crate::ffi::bindings::tls12_crypto_info_aes_gcm_128 {
                info: crate::ffi::bindings::tls_crypto_info {
                    version: ffi_version,
                    cipher_type: crate::ffi::bindings::TLS_CIPHER_AES_GCM_128 as _,
                },
                iv: Default::default(),
                key: Default::default(),
                salt: Default::default(),
                rec_seq: Default::default(),
            })
        }
        KtlsCipherType::AesGcm256 => {
            CryptoInfo::AesGcm256(crate::ffi::bindings::tls12_crypto_info_aes_gcm_256 {
                info: crate::ffi::bindings::tls_crypto_info {
                    version: ffi_version,
                    cipher_type: crate::ffi::bindings::TLS_CIPHER_AES_GCM_256 as _,
                },
                iv: Default::default(),
                key: Default::default(),
                salt: Default::default(),
                rec_seq: Default::default(),
            })
        }
        KtlsCipherType::Chacha20Poly1305 => CryptoInfo::Chacha20Poly1305(
            crate::ffi::bindings::tls12_crypto_info_chacha20_poly1305 {
                info: crate::ffi::bindings::tls_crypto_info {
                    version: ffi_version,
                    cipher_type: crate::ffi::bindings::TLS_CIPHER_CHACHA20_POLY1305 as _,
                },
                iv: Default::default(),
                key: Default::default(),
                salt: Default::default(),
                rec_seq: Default::default(),
            },
        ),
    };
    let fd = sock.as_raw_fd();

    crate::ffi::setup_ulp(fd).map_err(Error::UlpError)?;

    crate::ffi::setup_tls_info(fd, crate::ffi::Direction::Tx, crypto_info)?;

    Ok(())
}
