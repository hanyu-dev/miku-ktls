//! Setup kTLS stream.

use std::{
    io,
    os::fd::{AsRawFd, RawFd},
};

use rustls::ExtractedSecrets;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::{
    stream::{cork::CorkStream, KtlsStream},
    utils::async_read_ready::AsyncReadReady,
    Error,
};

/// The setup type being used to configure the kTLS stream.
///
/// See [`Setup::execute`] for details.
pub struct Setup<IO> {
    inner: Option<TlsStream<IO>>,
    drained: Option<Vec<u8>>,
}

impl<IO> Setup<IO> {
    #[inline]
    /// Initialize a new setup with the socket (that client connects to).
    pub const fn new_client_stream(inner: tokio_rustls::client::TlsStream<CorkStream<IO>>) -> Self
    where
        IO: AsRawFd + AsyncRead + AsyncWrite + Unpin,
    {
        Setup {
            inner: Some(TlsStream::Client(inner)),
            drained: None,
        }
    }

    #[inline]
    /// Initialize a new setup with the socket (that server accepts).
    pub const fn new_server_stream<'a>(
        inner: tokio_rustls::server::TlsStream<CorkStream<IO>>,
    ) -> Self
    where
        IO: AsRawFd + AsyncRead + AsyncReadReady<'a> + AsyncWrite + Unpin,
    {
        Setup {
            inner: Some(TlsStream::Server(inner)),
            drained: None,
        }
    }

    /// Try to recover from an error. This is used to allow the user to continue
    /// using the TLS stream after an error has occurred.
    ///
    /// This returns the inner TLS stream and the drained data.
    pub fn try_recover(&mut self) -> Option<(Option<Vec<u8>>, TlsStream<IO>)> {
        self.inner.take().map(|inner| (self.drained.take(), inner))
    }

    /// Execute kTLS configuration for this socket.
    ///
    /// If this call succeeds, data can be written and read from this socket,
    /// and the kernel takes care of encryption (and key updates, etc.)
    /// transparently.
    ///
    /// The inner IO type must be wrapped in [`CorkStream`] since it's the only
    /// way to drain a `rustls` stream cleanly. See its documentation for
    /// details.
    ///
    /// For server side, I'm not clear how rekeying is handled (probably via
    /// control messages, but can't find a code sample for it).
    pub async fn execute(&mut self) -> Result<KtlsStream<IO>, Error>
    where
        IO: AsRawFd + AsyncRead + AsyncWrite + Unpin,
    {
        {
            let Some(inner) = self.inner.as_ref() else {
                // rare: bug?
                return Err(crate::Error::ReuseAfterKtlsSetup);
            };

            crate::ffi::setup_ulp(inner.as_raw_fd()).map_err(Error::UlpError)?;
        }

        // The following steps may have errors and all of them are unrecoverable,
        // so we just take the inner TLS stream.

        let Some(mut inner) = self.inner.take() else {
            unreachable!("has checked for None");
        };

        {
            inner.set_corked(true);
            self.drained = inner.drain().await.map_err(Error::DrainError)?
        }

        let (CorkStream { io, .. }, tls_conn) = inner.into_inner();

        let cipher_suite = tls_conn
            .negotiated_cipher_suite()
            .ok_or(Error::NoNegotiatedCipherSuite)?;

        let ExtractedSecrets { tx, rx } = tls_conn
            .dangerous_extract_secrets()
            .map_err(Error::ExportSecrets)?;

        // Set up the kernel crypto info for the tx and rx directions
        {
            let fd = io.as_raw_fd();

            let tx = crate::ffi::CryptoInfo::from_rustls(cipher_suite, tx)?;
            crate::ffi::setup_tls_info(fd, crate::ffi::Direction::Tx, tx)?;

            let rx = crate::ffi::CryptoInfo::from_rustls(cipher_suite, rx)?;
            crate::ffi::setup_tls_info(fd, crate::ffi::Direction::Rx, rx)?;
        }

        Ok(KtlsStream::new(io, self.drained.take()))
    }
}

/// The TLS stream type. This is a wrapper around the tokio-rustls client and
/// server stream types. It is used to allow the `execute` method to return a
/// single type regardless of whether it is a client or server stream.
pub enum TlsStream<IO> {
    Client(tokio_rustls::client::TlsStream<CorkStream<IO>>),
    Server(tokio_rustls::server::TlsStream<CorkStream<IO>>),
}

impl<IO> TlsStream<IO> {
    #[inline]
    fn as_raw_fd(&self) -> RawFd
    where
        IO: AsRawFd,
    {
        match self {
            TlsStream::Client(stream) => stream.get_ref().0.io.as_raw_fd(),
            TlsStream::Server(stream) => stream.get_ref().0.io.as_raw_fd(),
        }
    }

    #[inline]
    fn set_corked(&mut self, corked: bool) {
        match self {
            TlsStream::Client(stream) => stream.get_mut().0.corked = corked,
            TlsStream::Server(stream) => stream.get_mut().0.corked = corked,
        }
    }

    #[inline]
    async fn drain(&mut self) -> io::Result<Option<Vec<u8>>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        match self {
            TlsStream::Client(stream) => drain(stream).await,
            TlsStream::Server(stream) => drain(stream).await,
        }
    }

    #[inline]
    fn into_inner(self) -> (CorkStream<IO>, rustls::Connection) {
        match self {
            TlsStream::Client(stream) => {
                let (io, tls_conn) = stream.into_inner();
                (io, rustls::Connection::Client(tls_conn))
            }
            TlsStream::Server(stream) => {
                let (io, tls_conn) = stream.into_inner();
                (io, rustls::Connection::Server(tls_conn))
            }
        }
    }
}

/// Read all the bytes we can read without blocking. This is used to drained the
/// already-decrypted buffer from a tokio-rustls I/O type
async fn drain(stream: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Option<Vec<u8>>> {
    tracing::trace!("Draining rustls stream");

    let mut drained = vec![0u8; 128 * 1024];
    let mut filled = 0;

    loop {
        tracing::trace!("stream.read called");

        let n = match stream.read(&mut drained[filled..]).await {
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // actually this is expected for us!
                tracing::trace!("stream.read returned UnexpectedEof, that's expected for us");
                break;
            }
            Err(e) => {
                tracing::trace!("stream.read returned error: {e}");
                return Err(e);
            }
        };
        tracing::trace!("stream.read returned {n}");
        if n == 0 {
            // that's what CorkStream returns when it's at a message boundary
            break;
        }
        filled += n;
    }

    let maybe_drained = if filled == 0 {
        None
    } else {
        tracing::trace!("Draining rustls stream done: drained {filled} bytes");
        drained.resize(filled, 0);
        Some(drained)
    };
    Ok(maybe_drained)
}

// === The deprecated code ===

#[deprecated(
    since = "7.0.0-rc.1",
    note = "use `Setup::new_server_stream(...).execute()` instead"
)]
/// See [`Setup::new_server_stream`] and [`Setup::execute`].
pub async fn config_ktls_server<'a, IO>(
    inner: tokio_rustls::server::TlsStream<CorkStream<IO>>,
) -> Result<KtlsStream<IO>, Error>
where
    IO: AsRawFd + AsyncRead + AsyncReadReady<'a> + AsyncWrite + Unpin,
{
    Setup::new_server_stream(inner).execute().await
}

#[deprecated(
    since = "7.0.0-rc.1",
    note = "use `Setup::new_client_stream(...).execute()` instead"
)]
/// See [`Setup::new_client_stream`] and [`Setup::execute`].
pub async fn config_ktls_client<IO>(
    inner: tokio_rustls::client::TlsStream<CorkStream<IO>>,
) -> Result<KtlsStream<IO>, Error>
where
    IO: AsRawFd + AsyncRead + AsyncWrite + Unpin,
{
    Setup::new_client_stream(inner).execute().await
}
