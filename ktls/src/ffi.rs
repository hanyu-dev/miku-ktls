use std::{io, mem::size_of_val, os::unix::io::RawFd, ptr::addr_of};

pub(crate) use ktls_sys::bindings;
use rustls::{
    internal::msgs::{enums::AlertLevel, message::Message},
    AlertDescription, ConnectionTrafficSecrets, SupportedCipherSuite,
};

use crate::error::KtlsCompatibilityError;

pub(crate) const TLS_1_2_VERSION_NUMBER: u16 = (((bindings::TLS_1_2_VERSION_MAJOR & 0xFF) as u16)
    << 8)
    | ((bindings::TLS_1_2_VERSION_MINOR & 0xFF) as u16);

pub(crate) const TLS_1_3_VERSION_NUMBER: u16 = (((bindings::TLS_1_3_VERSION_MAJOR & 0xFF) as u16)
    << 8)
    | ((bindings::TLS_1_3_VERSION_MINOR & 0xFF) as u16);

/// `setsockopt` level constant: TCP
const SOL_TCP: libc::c_int = 6;

/// `setsockopt` SOL_TCP name constant: "upper level protocol"
const TCP_ULP: libc::c_int = 31;

/// `setsockopt` level constant: TLS
const SOL_TLS: libc::c_int = 282;

/// `setsockopt` SOL_TLS level constant: transmit (write)
const TLS_TX: libc::c_int = 1;

/// `setsockopt` SOL_TLS level constant: receive (read)
const TLS_RX: libc::c_int = 2;

/// `setsockopt(fd, SOL_TCP, TCP_ULP, "tls", size_of("tls"))`
pub(crate) fn setup_ulp(fd: RawFd) -> io::Result<()> {
    unsafe {
        if libc::setsockopt(
            fd,
            SOL_TCP,
            TCP_ULP,
            "tls".as_ptr() as *const libc::c_void,
            3,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

/// `setsockopt(fd, SOL_TLS, {TLS_TX or TLS_RX}, info, size_of(info))`
pub(crate) fn setup_tls_info(
    fd: RawFd,
    dir: Direction,
    info: CryptoInfo,
) -> Result<(), crate::Error> {
    unsafe {
        if libc::setsockopt(fd, SOL_TLS, dir.as_c_int(), info.as_ptr(), info.size() as _) < 0 {
            return Err(crate::Error::TlsCryptoInfoError(io::Error::last_os_error()));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
/// `SOL_TLS` direction.
pub enum Direction {
    // Transmit
    Tx,

    // Receive
    Rx,
}

impl Direction {
    #[inline]
    const fn as_c_int(self) -> libc::c_int {
        match self {
            Self::Tx => TLS_TX,
            Self::Rx => TLS_RX,
        }
    }
}

#[allow(dead_code)]
/// `SOL_TLS` crypto info.
///
/// This is a wrapper around the kernel structs.
pub enum CryptoInfo {
    AesGcm128(bindings::tls12_crypto_info_aes_gcm_128),
    AesGcm256(bindings::tls12_crypto_info_aes_gcm_256),
    AesCcm128(bindings::tls12_crypto_info_aes_ccm_128),
    Chacha20Poly1305(bindings::tls12_crypto_info_chacha20_poly1305),
    Sm4Gcm(bindings::tls12_crypto_info_sm4_gcm),
    Sm4Ccm(bindings::tls12_crypto_info_sm4_ccm),
}

impl CryptoInfo {
    /// Return the system struct as a raw pointer.
    pub fn as_ptr(&self) -> *const libc::c_void {
        match self {
            Self::AesGcm128(info) => addr_of!(info) as *const libc::c_void,
            Self::AesGcm256(info) => addr_of!(info) as *const libc::c_void,
            Self::AesCcm128(info) => addr_of!(info) as *const libc::c_void,
            Self::Chacha20Poly1305(info) => addr_of!(info) as *const libc::c_void,
            Self::Sm4Gcm(info) => addr_of!(info) as *const libc::c_void,
            Self::Sm4Ccm(info) => addr_of!(info) as *const libc::c_void,
        }
    }

    #[inline]
    /// Return the system struct size.
    pub fn size(&self) -> usize {
        match self {
            Self::AesGcm128(info) => size_of_val(info),
            Self::AesGcm256(info) => size_of_val(info),
            Self::AesCcm128(info) => size_of_val(info),
            Self::Chacha20Poly1305(info) => size_of_val(info),
            Self::Sm4Gcm(info) => size_of_val(info),
            Self::Sm4Ccm(info) => size_of_val(info),
        }
    }
}

impl CryptoInfo {
    /// Try to convert rustls cipher suite and secrets into a `CryptoInfo`.
    pub fn from_rustls(
        cipher_suite: SupportedCipherSuite,
        (seq, secrets): (u64, ConnectionTrafficSecrets),
    ) -> Result<CryptoInfo, KtlsCompatibilityError> {
        let version = match cipher_suite {
            SupportedCipherSuite::Tls12(..) => TLS_1_2_VERSION_NUMBER,
            SupportedCipherSuite::Tls13(..) => TLS_1_3_VERSION_NUMBER,
        };

        Ok(match secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                // see https://github.com/rustls/rustls/issues/1833, between
                // rustls 0.21 and 0.22, the extract_keys codepath was changed,
                // so, for TLS 1.2, both GCM-128 and GCM-256 return the
                // Aes128Gcm variant.

                match key.as_ref().len() {
                    16 => CryptoInfo::AesGcm128(bindings::tls12_crypto_info_aes_gcm_128 {
                        info: bindings::tls_crypto_info {
                            version,
                            cipher_type: bindings::TLS_CIPHER_AES_GCM_128 as _,
                        },
                        iv: iv
                            .as_ref()
                            .get(4..)
                            .expect("AES-GCM-128 iv is 8 bytes")
                            .try_into()
                            .expect("AES-GCM-128 iv is 8 bytes"),
                        key: key
                            .as_ref()
                            .try_into()
                            .expect("AES-GCM-128 key is 16 bytes"),
                        salt: iv
                            .as_ref()
                            .get(..4)
                            .expect("AES-GCM-128 salt is 4 bytes")
                            .try_into()
                            .expect("AES-GCM-128 salt is 4 bytes"),
                        rec_seq: seq.to_be_bytes(),
                    }),
                    32 => CryptoInfo::AesGcm256(bindings::tls12_crypto_info_aes_gcm_256 {
                        info: bindings::tls_crypto_info {
                            version,
                            cipher_type: bindings::TLS_CIPHER_AES_GCM_256 as _,
                        },
                        iv: iv
                            .as_ref()
                            .get(4..)
                            .expect("AES-GCM-256 iv is 8 bytes")
                            .try_into()
                            .expect("AES-GCM-256 iv is 8 bytes"),
                        key: key
                            .as_ref()
                            .try_into()
                            .expect("AES-GCM-256 key is 32 bytes"),
                        salt: iv
                            .as_ref()
                            .get(..4)
                            .expect("AES-GCM-256 salt is 4 bytes")
                            .try_into()
                            .expect("AES-GCM-256 salt is 4 bytes"),
                        rec_seq: seq.to_be_bytes(),
                    }),
                    _ => unreachable!("GCM key length is not 16 or 32"),
                }
            }
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
                CryptoInfo::AesGcm256(bindings::tls12_crypto_info_aes_gcm_256 {
                    info: bindings::tls_crypto_info {
                        version,
                        cipher_type: bindings::TLS_CIPHER_AES_GCM_256 as _,
                    },
                    iv: iv
                        .as_ref()
                        .get(4..)
                        .expect("AES-GCM-256 iv is 8 bytes")
                        .try_into()
                        .expect("AES-GCM-256 iv is 8 bytes"),
                    key: key
                        .as_ref()
                        .try_into()
                        .expect("AES-GCM-256 key is 32 bytes"),
                    salt: iv
                        .as_ref()
                        .get(..4)
                        .expect("AES-GCM-256 salt is 4 bytes")
                        .try_into()
                        .expect("AES-GCM-256 salt is 4 bytes"),
                    rec_seq: seq.to_be_bytes(),
                })
            }
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                CryptoInfo::Chacha20Poly1305(bindings::tls12_crypto_info_chacha20_poly1305 {
                    info: bindings::tls_crypto_info {
                        version,
                        cipher_type: bindings::TLS_CIPHER_CHACHA20_POLY1305 as _,
                    },
                    iv: iv
                        .as_ref()
                        .try_into()
                        .expect("Chacha20-Poly1305 iv is 12 bytes"),
                    key: key
                        .as_ref()
                        .try_into()
                        .expect("Chacha20-Poly1305 key is 32 bytes"),
                    salt: bindings::__IncompleteArrayField::new(),
                    rec_seq: seq.to_be_bytes(),
                })
            }
            _ => {
                return Err(KtlsCompatibilityError::UnsupportedCipherSuite(cipher_suite));
            }
        })
    }
}

const TLS_SET_RECORD_TYPE: libc::c_int = 1;
const ALERT: u8 = 0x15;

// Yes, really. cmsg components are aligned to [libc::c_long]
#[cfg_attr(target_pointer_width = "32", repr(C, align(4)))]
#[cfg_attr(target_pointer_width = "64", repr(C, align(8)))]
struct Cmsg<const N: usize> {
    hdr: libc::cmsghdr,
    data: [u8; N],
}

impl<const N: usize> Cmsg<N> {
    fn new(level: i32, typ: i32, data: [u8; N]) -> Self {
        Self {
            hdr: libc::cmsghdr {
                // on Linux this is a usize, on macOS this is a u32
                #[allow(clippy::unnecessary_cast)]
                cmsg_len: (memoffset::offset_of!(Self, data) + N) as _,
                cmsg_level: level,
                cmsg_type: typ,
            },
            data,
        }
    }
}

pub(crate) fn send_close_notify(fd: RawFd) -> std::io::Result<()> {
    let mut data = vec![];
    Message::build_alert(AlertLevel::Warning, AlertDescription::CloseNotify)
        .payload
        .encode(&mut data);

    let mut cmsg = Cmsg::new(SOL_TLS, TLS_SET_RECORD_TYPE, [ALERT]);

    let msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut libc::iovec {
            iov_base: data.as_mut_ptr() as _,
            iov_len: data.len(),
        },
        msg_iovlen: 1,
        msg_control: &mut cmsg as *mut _ as *mut _,
        msg_controllen: cmsg.hdr.cmsg_len,
        msg_flags: 0,
    };

    let ret = unsafe { libc::sendmsg(fd, &msg, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
