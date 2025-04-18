//! Cipher suites

#[cfg(all(not(feature = "ring"), not(feature = "aws-lc-rs")))]
compile_error!("This crate needs either the 'ring' or 'aws-lc-rs' feature enabled");
#[cfg(all(feature = "ring", feature = "aws-lc-rs"))]
compile_error!("The 'ring' and 'aws-lc-rs' features are mutually exclusive");

#[cfg(feature = "aws-lc-rs")]
pub use rustls::crypto::aws_lc_rs::cipher_suite::*;
#[cfg(feature = "ring")]
pub use rustls::crypto::ring::cipher_suite::*;
