//! Helper trait: for any type that has a `poll_read_ready` method.

use std::{
    io,
    os::fd::AsRawFd,
    task::{Context, Poll},
};

use tokio::{
    io::unix::{AsyncFd, AsyncFdReadyGuard},
    net::{TcpStream, UnixStream},
};

/// Helper trait: for any type that has a `poll_read_ready` method.
pub trait AsyncReadReady<'a> {
    type Output;

    /// cf. https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html#method.poll_read_ready
    fn poll_read_ready(&'a self, cx: &mut Context<'_>) -> Poll<Self::Output>;
}

impl AsyncReadReady<'_> for TcpStream {
    type Output = io::Result<()>;

    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<Self::Output> {
        TcpStream::poll_read_ready(self, cx)
    }
}

impl AsyncReadReady<'_> for UnixStream {
    type Output = io::Result<()>;

    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<Self::Output> {
        UnixStream::poll_read_ready(self, cx)
    }
}

impl<'a, T: AsRawFd + 'a> AsyncReadReady<'a> for AsyncFd<T> {
    type Output = io::Result<AsyncFdReadyGuard<'a, T>>;

    fn poll_read_ready(&'a self, cx: &mut Context<'_>) -> Poll<Self::Output> {
        AsyncFd::poll_read_ready(self, cx)
    }
}
