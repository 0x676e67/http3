//! TLS context management.
//!
//! Integrates `ngtcp2_crypto_boringssl` with aws-lc and manages TLS contexts
//! for QUIC connections.
//!
//! # Design
//!
//! - `TlsContext`: wraps `SSL_CTX` and stores shared server/client settings.
//! - `TlsSession`: wraps `SSL` for an individual connection.
//!
//! Calling `ngtcp2_crypto_boringssl_configure_*_context()` installs the TLS
//! callbacks required by ngtcp2.

use std::ffi::{CString, c_void};
use std::path::Path;

use aws_lc_sys::{
    SSL, SSL_CTX, SSL_CTX_free, SSL_CTX_new, SSL_CTX_set_alpn_protos, SSL_CTX_use_PrivateKey_file,
    SSL_CTX_use_certificate_chain_file, SSL_FILETYPE_PEM, SSL_free, SSL_new, SSL_set_accept_state,
    SSL_set_connect_state, SSL_set_tlsext_host_name, TLS_method,
};
use ngtcp2_sys::{
    ngtcp2_crypto_boringssl_configure_client_context,
    ngtcp2_crypto_boringssl_configure_server_context,
};

use crate::error::{Error, Result};

/// TLS context.
///
/// Wraps `SSL_CTX` and provides the settings required for QUIC connections.
/// One context can be created for server or client use and can produce multiple
/// `TlsSession` values.
pub struct TlsContext {
    ctx: *mut SSL_CTX,
    is_server: bool,
    // Data used by the ALPN callback on servers. Keep the pointer passed to the
    // callback and free it in Drop.
    alpn_data: Option<*mut Vec<u8>>,
}

// SAFETY: TlsContext owns an SSL_CTX and may be moved with its owner. Shared
// cross-thread access is not required by the interop drivers.
unsafe impl Send for TlsContext {}

impl TlsContext {
    /// Creates a client TLS context.
    ///
    /// # Arguments
    ///
    /// * `alpn` - ALPN protocol list, for example `&[b"h3"]`.
    pub fn new_client(alpn: &[&[u8]]) -> Result<Self> {
        Self::new_client_with_options(alpn, true)
    }

    /// Creates a client TLS context with additional options.
    ///
    /// # Arguments
    ///
    /// * `alpn` - ALPN protocol list, for example `&[b"h3"]`.
    /// * `verify_peer` - Whether to verify the server certificate.
    pub fn new_client_with_options(alpn: &[&[u8]], verify_peer: bool) -> Result<Self> {
        unsafe {
            let method = TLS_method();
            if method.is_null() {
                return Err(Error::Internal("TLS_method failed".to_string()));
            }

            let ctx = SSL_CTX_new(method);
            if ctx.is_null() {
                return Err(Error::Internal("SSL_CTX_new failed".to_string()));
            }

            // Apply ngtcp2 settings.
            // SAFETY: aws_lc_sys::SSL_CTX and ngtcp2_sys::SSL_CTX refer to the
            // same aws-lc/BoringSSL SSL_CTX type.
            let rv =
                ngtcp2_crypto_boringssl_configure_client_context(ctx as *mut ngtcp2_sys::SSL_CTX);
            if rv != 0 {
                SSL_CTX_free(ctx);
                return Err(Error::Internal(
                    "ngtcp2_crypto_boringssl_configure_client_context failed".to_string(),
                ));
            }

            // Configure certificate verification.
            if !verify_peer {
                // Disable verification for self-signed certificates in tests.
                aws_lc_sys::SSL_CTX_set_verify(ctx, aws_lc_sys::SSL_VERIFY_NONE, None);
            }

            // Configure ALPN.
            let alpn_wire = Self::encode_alpn(alpn);
            let rv = SSL_CTX_set_alpn_protos(ctx, alpn_wire.as_ptr(), alpn_wire.len());
            if rv != 0 {
                SSL_CTX_free(ctx);
                return Err(Error::Internal(
                    "SSL_CTX_set_alpn_protos failed".to_string(),
                ));
            }

            Ok(Self {
                ctx,
                is_server: false,
                alpn_data: None,
            })
        }
    }

    /// Creates a server TLS context.
    ///
    /// # Arguments
    ///
    /// * `cert_path` - Path to the certificate file in PEM format.
    /// * `key_path` - Path to the private key file in PEM format.
    /// * `alpn` - ALPN protocol list, for example `&[b"h3"]`.
    pub fn new_server(cert_path: &Path, key_path: &Path, alpn: &[&[u8]]) -> Result<Self> {
        unsafe {
            let method = TLS_method();
            if method.is_null() {
                return Err(Error::Internal("TLS_method failed".to_string()));
            }

            let ctx = SSL_CTX_new(method);
            if ctx.is_null() {
                return Err(Error::Internal("SSL_CTX_new failed".to_string()));
            }

            // Apply ngtcp2 settings.
            // SAFETY: aws_lc_sys::SSL_CTX and ngtcp2_sys::SSL_CTX refer to the
            // same aws-lc/BoringSSL SSL_CTX type.
            let rv =
                ngtcp2_crypto_boringssl_configure_server_context(ctx as *mut ngtcp2_sys::SSL_CTX);
            if rv != 0 {
                SSL_CTX_free(ctx);
                return Err(Error::Internal(
                    "ngtcp2_crypto_boringssl_configure_server_context failed".to_string(),
                ));
            }

            // Load the certificate chain.
            let cert_path_cstr = CString::new(cert_path.to_string_lossy().as_bytes())
                .map_err(|_| Error::InvalidArgument("invalid cert path".to_string()))?;
            let rv = SSL_CTX_use_certificate_chain_file(ctx, cert_path_cstr.as_ptr());
            if rv != 1 {
                SSL_CTX_free(ctx);
                return Err(Error::Internal(format!(
                    "SSL_CTX_use_certificate_chain_file failed: {}",
                    cert_path.display()
                )));
            }

            // Load the private key.
            let key_path_cstr = CString::new(key_path.to_string_lossy().as_bytes())
                .map_err(|_| Error::InvalidArgument("invalid key path".to_string()))?;
            let rv = SSL_CTX_use_PrivateKey_file(ctx, key_path_cstr.as_ptr(), SSL_FILETYPE_PEM);
            if rv != 1 {
                SSL_CTX_free(ctx);
                return Err(Error::Internal(format!(
                    "SSL_CTX_use_PrivateKey_file failed: {}",
                    key_path.display()
                )));
            }

            // Configure the server-side ALPN callback.
            let alpn_wire = Self::encode_alpn(alpn);
            let alpn_data = Box::new(alpn_wire);
            let alpn_ptr = Box::into_raw(alpn_data);

            aws_lc_sys::SSL_CTX_set_alpn_select_cb(
                ctx,
                Some(alpn_select_callback),
                alpn_ptr as *mut c_void,
            );

            Ok(Self {
                ctx,
                is_server: true,
                alpn_data: Some(alpn_ptr),
            })
        }
    }

    /// Creates a TLS session.
    pub fn create_session(&self) -> Result<TlsSession> {
        unsafe {
            let ssl = SSL_new(self.ctx);
            if ssl.is_null() {
                return Err(Error::Internal("SSL_new failed".to_string()));
            }

            if self.is_server {
                SSL_set_accept_state(ssl);
            } else {
                SSL_set_connect_state(ssl);
            }

            Ok(TlsSession {
                ssl,
                is_server: self.is_server,
            })
        }
    }

    /// Encodes an ALPN protocol list into wire format.
    ///
    /// Wire format: `[len1][proto1][len2][proto2]...`.
    fn encode_alpn(alpn: &[&[u8]]) -> Vec<u8> {
        let mut wire = Vec::new();
        for proto in alpn {
            wire.push(proto.len() as u8);
            wire.extend_from_slice(proto);
        }
        wire
    }

    /// Returns the inner pointer.
    pub fn as_ptr(&self) -> *mut SSL_CTX {
        self.ctx
    }
}

impl Drop for TlsContext {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            unsafe {
                // Free the data installed for the ALPN callback.
                if let Some(alpn_ptr) = self.alpn_data {
                    let _ = Box::from_raw(alpn_ptr);
                }
                SSL_CTX_free(self.ctx);
            }
        }
    }
}

/// TLS session.
///
/// Wraps `SSL` for an individual QUIC connection.
pub struct TlsSession {
    ssl: *mut SSL,
    is_server: bool,
}

// SAFETY: TlsSession owns one SSL object and moves with its QUIC connection.
// The wrapper does not promise shared cross-thread access to SSL.
unsafe impl Send for TlsSession {}

impl TlsSession {
    /// Sets SNI (Server Name Indication).
    ///
    /// Used by client connections to specify the peer server name.
    pub fn set_server_name(&mut self, server_name: &str) -> Result<()> {
        if self.is_server {
            return Err(Error::InvalidArgument(
                "cannot set server name on server session".to_string(),
            ));
        }

        let server_name_cstr = CString::new(server_name)
            .map_err(|_| Error::InvalidArgument("invalid server name".to_string()))?;

        unsafe {
            let rv = SSL_set_tlsext_host_name(self.ssl, server_name_cstr.as_ptr());
            if rv != 1 {
                return Err(Error::Internal(
                    "SSL_set_tlsext_host_name failed".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Sets QUIC transport parameters.
    ///
    /// Must be called before attaching the session to an `ngtcp2_conn`.
    pub fn set_quic_transport_params(&mut self, params: &[u8]) -> Result<()> {
        unsafe {
            let rv =
                aws_lc_sys::SSL_set_quic_transport_params(self.ssl, params.as_ptr(), params.len());
            if rv != 1 {
                return Err(Error::Internal(
                    "SSL_set_quic_transport_params failed".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Returns the inner pointer.
    pub fn as_ptr(&self) -> *mut SSL {
        self.ssl
    }

    /// Returns the inner pointer as `c_void` for ngtcp2.
    pub fn as_void_ptr(&self) -> *mut c_void {
        self.ssl as *mut c_void
    }

    /// Returns whether this is a server session.
    pub fn is_server(&self) -> bool {
        self.is_server
    }
}

impl Drop for TlsSession {
    fn drop(&mut self) {
        if !self.ssl.is_null() {
            unsafe {
                SSL_free(self.ssl);
            }
        }
    }
}

/// ALPN selection callback for servers.
///
/// Selects a server-supported protocol from the client's ALPN list.
unsafe extern "C" fn alpn_select_callback(
    _ssl: *mut SSL,
    out: *mut *const u8,
    outlen: *mut u8,
    client_alpn: *const u8,
    client_alpn_len: u32,
    arg: *mut c_void,
) -> i32 {
    const SSL_TLSEXT_ERR_OK: i32 = 0;
    const SSL_TLSEXT_ERR_NOACK: i32 = 3;

    if arg.is_null()
        || out.is_null()
        || outlen.is_null()
        || (client_alpn.is_null() && client_alpn_len > 0)
    {
        return SSL_TLSEXT_ERR_NOACK;
    }

    // SAFETY: arg is the Vec<u8> pointer created by TlsContext::new_server.
    let server_alpn = unsafe { &*(arg as *const Vec<u8>) };
    let client_alpn_slice = if client_alpn_len == 0 {
        &[][..]
    } else {
        // SAFETY: non-empty client ALPN input has a non-null pointer checked
        // above and is owned by the TLS library for this callback.
        unsafe { std::slice::from_raw_parts(client_alpn, client_alpn_len as usize) }
    };

    // Parse the server ALPN list.
    let mut server_pos = 0;
    while server_pos < server_alpn.len() {
        let server_proto_len = server_alpn[server_pos] as usize;
        server_pos += 1;
        if server_pos + server_proto_len > server_alpn.len() {
            break;
        }
        let server_proto = &server_alpn[server_pos..server_pos + server_proto_len];
        server_pos += server_proto_len;

        // Parse the client ALPN list.
        let mut client_pos = 0;
        while client_pos < client_alpn_slice.len() {
            let client_proto_len = client_alpn_slice[client_pos] as usize;
            client_pos += 1;
            if client_pos + client_proto_len > client_alpn_slice.len() {
                break;
            }
            let client_proto = &client_alpn_slice[client_pos..client_pos + client_proto_len];
            client_pos += client_proto_len;

            // A matching protocol was found.
            if server_proto == client_proto {
                // SAFETY: out and outlen are valid pointers from the caller.
                unsafe {
                    *out = client_alpn.add(client_pos - client_proto_len);
                    *outlen = client_proto_len as u8;
                }
                return SSL_TLSEXT_ERR_OK;
            }
        }
    }

    SSL_TLSEXT_ERR_NOACK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_alpn() {
        let alpn = TlsContext::encode_alpn(&[b"h3", b"h3-29"]);
        assert_eq!(alpn, vec![2, b'h', b'3', 5, b'h', b'3', b'-', b'2', b'9']);
    }

    #[test]
    fn test_client_context_creation() {
        let ctx = TlsContext::new_client(&[b"h3"]);
        assert!(ctx.is_ok());
    }
}
