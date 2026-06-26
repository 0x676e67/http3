use std::collections::VecDeque;
use std::ffi::c_void;
use std::net::SocketAddr;
use std::ptr;

use libc::c_int;
use ngtcp2_sys::*;

use crate::crypto::TlsSession;
use crate::error::{Error, Result, check_ngtcp2};
use crate::types::{ConnectionId, PacketInfo, QuicVersion, StreamId};

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_IN6_0, SOCKADDR_STORAGE,
};

#[cfg(windows)]
type RawSockAddrStorage = SOCKADDR_STORAGE;

#[cfg(not(windows))]
type RawSockAddrStorage = libc::sockaddr_storage;

/// Stream data event.
#[derive(Debug, Clone)]
pub struct StreamData {
    /// Stream ID.
    pub stream_id: StreamId,
    /// Received data.
    pub data: Vec<u8>,
    /// Stream end flag.
    pub fin: bool,
}

/// DATAGRAM event.
#[derive(Debug, Clone)]
pub struct Datagram {
    /// Datagram data.
    pub data: Vec<u8>,
}

/// QUIC connection.
pub struct Connection {
    inner: *mut ngtcp2_conn,
    // User data passed to callbacks.
    user_data: Box<ConnectionUserData>,
    // TLS session used by the high-level API.
    _tls_session: Option<TlsSession>,
    // ngtcp2_crypto_conn_ref installed into SSL by the high-level API.
    _conn_ref: Option<Box<ConnRef>>,
}

struct ConnectionUserData {
    // Queue for received stream data.
    stream_data_queue: VecDeque<StreamData>,
    // Queue for received DATAGRAM frames.
    datagram_queue: VecDeque<Datagram>,
}

/// Wrapper for `ngtcp2_crypto_conn_ref`.
///
/// Stored on SSL with `SSL_set_app_data` so TLS callbacks can recover the
/// `ngtcp2_conn`.
struct ConnRef {
    inner: ngtcp2_crypto_conn_ref,
}

// SAFETY: Connection owns the ngtcp2 state machine and is only moved between
// tasks with exclusive access. ngtcp2_conn itself is not exposed as Sync.
unsafe impl Send for Connection {}

impl Connection {
    /// Creates a client connection using the low-level API.
    ///
    /// The caller owns callbacks and `user_data`. `poll_stream_data()` and
    /// `poll_datagram()` cannot be used because those callbacks do not write to
    /// the internal queues.
    ///
    /// # Safety
    /// `callbacks` and `settings` must be valid pointers.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn client_new_raw(
        dcid: &ConnectionId,
        scid: &ConnectionId,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        version: u32,
        callbacks: *const ngtcp2_callbacks,
        settings: *const ngtcp2_settings,
        params: *const ngtcp2_transport_params,
        user_data: *mut c_void,
    ) -> Result<Self> {
        let mut conn: *mut ngtcp2_conn = ptr::null_mut();

        let dcid_raw = cid_to_raw(dcid);
        let scid_raw = cid_to_raw(scid);

        let (local_sockaddr, local_len) = sockaddr_to_raw(&local_addr);
        let (remote_sockaddr, remote_len) = sockaddr_to_raw(&remote_addr);

        let path = ngtcp2_path {
            local: ngtcp2_addr {
                addr: &local_sockaddr as *const _ as *mut _,
                addrlen: local_len,
            },
            remote: ngtcp2_addr {
                addr: &remote_sockaddr as *const _ as *mut _,
                addrlen: remote_len,
            },
            user_data: ptr::null_mut(),
        };

        let rv = unsafe {
            ngtcp2_conn_client_new_versioned(
                &mut conn,
                &dcid_raw,
                &scid_raw,
                &path,
                version,
                NGTCP2_CALLBACKS_VERSION as c_int,
                callbacks,
                NGTCP2_SETTINGS_VERSION as c_int,
                settings,
                NGTCP2_TRANSPORT_PARAMS_VERSION as c_int,
                params,
                ptr::null(),
                user_data,
            )
        };

        check_ngtcp2(rv)?;

        let user_data_box = Box::new(ConnectionUserData {
            stream_data_queue: VecDeque::new(),
            datagram_queue: VecDeque::new(),
        });

        Ok(Self {
            inner: conn,
            user_data: user_data_box,
            _tls_session: None,
            _conn_ref: None,
        })
    }

    /// Creates a server connection using the low-level API.
    ///
    /// The caller owns callbacks and `user_data`. `poll_stream_data()` and
    /// `poll_datagram()` cannot be used because those callbacks do not write to
    /// the internal queues.
    ///
    /// # Safety
    /// `callbacks` and `settings` must be valid pointers.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn server_new_raw(
        dcid: &ConnectionId,
        scid: &ConnectionId,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        version: u32,
        callbacks: *const ngtcp2_callbacks,
        settings: *const ngtcp2_settings,
        params: *const ngtcp2_transport_params,
        user_data: *mut c_void,
    ) -> Result<Self> {
        let mut conn: *mut ngtcp2_conn = ptr::null_mut();

        let dcid_raw = cid_to_raw(dcid);
        let scid_raw = cid_to_raw(scid);

        let (local_sockaddr, local_len) = sockaddr_to_raw(&local_addr);
        let (remote_sockaddr, remote_len) = sockaddr_to_raw(&remote_addr);

        let path = ngtcp2_path {
            local: ngtcp2_addr {
                addr: &local_sockaddr as *const _ as *mut _,
                addrlen: local_len,
            },
            remote: ngtcp2_addr {
                addr: &remote_sockaddr as *const _ as *mut _,
                addrlen: remote_len,
            },
            user_data: ptr::null_mut(),
        };

        let rv = unsafe {
            ngtcp2_conn_server_new_versioned(
                &mut conn,
                &dcid_raw,
                &scid_raw,
                &path,
                version,
                NGTCP2_CALLBACKS_VERSION as c_int,
                callbacks,
                NGTCP2_SETTINGS_VERSION as c_int,
                settings,
                NGTCP2_TRANSPORT_PARAMS_VERSION as c_int,
                params,
                ptr::null(),
                user_data,
            )
        };

        check_ngtcp2(rv)?;

        let user_data_box = Box::new(ConnectionUserData {
            stream_data_queue: VecDeque::new(),
            datagram_queue: VecDeque::new(),
        });

        Ok(Self {
            inner: conn,
            user_data: user_data_box,
            _tls_session: None,
            _conn_ref: None,
        })
    }

    /// Creates a client connection using the high-level API.
    ///
    /// Installs ngtcp2_crypto callbacks and manages the TLS session.
    ///
    /// # Arguments
    ///
    /// * `dcid` - Destination connection ID.
    /// * `scid` - Source connection ID.
    /// * `local_addr` - Local address.
    /// * `remote_addr` - Remote address.
    /// * `server_name` - Server name for SNI.
    /// * `tls_session` - TLS session.
    /// * `params` - Transport parameters.
    /// * `initial_ts` - Initial timestamp in nanoseconds.
    #[allow(clippy::too_many_arguments)]
    pub fn client_new(
        dcid: &ConnectionId,
        scid: &ConnectionId,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        server_name: &str,
        mut tls_session: TlsSession,
        params: &ngtcp2_transport_params,
        initial_ts: u64,
    ) -> Result<Self> {
        // Configure SNI.
        tls_session.set_server_name(server_name)?;

        // Configure callbacks.
        let callbacks = create_client_callbacks();

        // Build settings.
        let mut settings: ngtcp2_settings = unsafe { std::mem::zeroed() };
        unsafe {
            ngtcp2_settings_default_versioned(NGTCP2_SETTINGS_VERSION as c_int, &mut settings);
        }
        settings.initial_ts = initial_ts;
        settings.max_tx_udp_payload_size = 1350;

        // Build user data.
        let mut user_data_box = Box::new(ConnectionUserData {
            stream_data_queue: VecDeque::new(),
            datagram_queue: VecDeque::new(),
        });
        let user_data_ptr = &mut *user_data_box as *mut ConnectionUserData as *mut c_void;

        let mut conn: *mut ngtcp2_conn = ptr::null_mut();

        let dcid_raw = cid_to_raw(dcid);
        let scid_raw = cid_to_raw(scid);

        let (local_sockaddr, local_len) = sockaddr_to_raw(&local_addr);
        let (remote_sockaddr, remote_len) = sockaddr_to_raw(&remote_addr);

        let path = ngtcp2_path {
            local: ngtcp2_addr {
                addr: &local_sockaddr as *const _ as *mut _,
                addrlen: local_len,
            },
            remote: ngtcp2_addr {
                addr: &remote_sockaddr as *const _ as *mut _,
                addrlen: remote_len,
            },
            user_data: ptr::null_mut(),
        };

        let rv = unsafe {
            ngtcp2_conn_client_new_versioned(
                &mut conn,
                &dcid_raw,
                &scid_raw,
                &path,
                QuicVersion::V1 as u32,
                NGTCP2_CALLBACKS_VERSION as c_int,
                &callbacks,
                NGTCP2_SETTINGS_VERSION as c_int,
                &settings,
                NGTCP2_TRANSPORT_PARAMS_VERSION as c_int,
                params,
                ptr::null(),
                user_data_ptr,
            )
        };

        check_ngtcp2(rv)?;

        // Create conn_ref so TLS callbacks can recover ngtcp2_conn.
        let mut conn_ref = Box::new(ConnRef {
            inner: ngtcp2_crypto_conn_ref {
                get_conn: Some(conn_ref_get_conn_callback),
                user_data: conn as *mut c_void,
            },
        });

        // Store conn_ref on SSL. SSL_set_app_data is a macro for
        // SSL_set_ex_data(ssl, 0, data).
        let conn_ref_ptr = &mut conn_ref.inner as *mut ngtcp2_crypto_conn_ref;
        unsafe {
            aws_lc_sys::SSL_set_ex_data(tls_session.as_ptr(), 0, conn_ref_ptr as *mut c_void);
        }

        // Set the native TLS handle.
        unsafe {
            ngtcp2_conn_set_tls_native_handle(conn, tls_session.as_void_ptr());
        }

        // Set client transport parameters on TLS. ngtcp2_crypto's
        // client_initial_cb also sets them, but doing it here keeps aws-lc
        // behavior explicit for tests.
        let mut tp_buf = [0u8; 512];
        let tp_len = unsafe {
            ngtcp2_conn_encode_local_transport_params(conn, tp_buf.as_mut_ptr(), tp_buf.len())
        };
        if tp_len < 0 {
            unsafe { ngtcp2_conn_del(conn) };
            return Err(Error::from_ngtcp2(tp_len as i32));
        }
        if let Err(e) = tls_session.set_quic_transport_params(&tp_buf[..tp_len as usize]) {
            unsafe { ngtcp2_conn_del(conn) };
            return Err(e);
        }

        Ok(Self {
            inner: conn,
            user_data: user_data_box,
            _tls_session: Some(tls_session),
            _conn_ref: Some(conn_ref),
        })
    }

    /// Creates a server connection using the high-level API.
    ///
    /// Installs ngtcp2_crypto callbacks and manages the TLS session.
    ///
    /// # Arguments
    ///
    /// * `dcid` - Destination connection ID, received as the client's SCID.
    /// * `scid` - Source connection ID generated by the server.
    /// * `local_addr` - Local address.
    /// * `remote_addr` - Remote address.
    /// * `tls_session` - TLS session.
    /// * `params` - Transport parameters.
    /// * `initial_ts` - Initial timestamp in nanoseconds.
    #[allow(clippy::too_many_arguments)]
    pub fn server_new(
        dcid: &ConnectionId,
        scid: &ConnectionId,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        mut tls_session: TlsSession,
        params: &ngtcp2_transport_params,
        initial_ts: u64,
    ) -> Result<Self> {
        // Configure callbacks.
        let callbacks = create_server_callbacks();

        // Build settings.
        let mut settings: ngtcp2_settings = unsafe { std::mem::zeroed() };
        unsafe {
            ngtcp2_settings_default_versioned(NGTCP2_SETTINGS_VERSION as c_int, &mut settings);
        }
        settings.initial_ts = initial_ts;
        settings.max_tx_udp_payload_size = 1350;

        // Build user data.
        let mut user_data_box = Box::new(ConnectionUserData {
            stream_data_queue: VecDeque::new(),
            datagram_queue: VecDeque::new(),
        });
        let user_data_ptr = &mut *user_data_box as *mut ConnectionUserData as *mut c_void;

        let mut conn: *mut ngtcp2_conn = ptr::null_mut();

        let dcid_raw = cid_to_raw(dcid);
        let scid_raw = cid_to_raw(scid);

        let (local_sockaddr, local_len) = sockaddr_to_raw(&local_addr);
        let (remote_sockaddr, remote_len) = sockaddr_to_raw(&remote_addr);

        let path = ngtcp2_path {
            local: ngtcp2_addr {
                addr: &local_sockaddr as *const _ as *mut _,
                addrlen: local_len,
            },
            remote: ngtcp2_addr {
                addr: &remote_sockaddr as *const _ as *mut _,
                addrlen: remote_len,
            },
            user_data: ptr::null_mut(),
        };

        let rv = unsafe {
            ngtcp2_conn_server_new_versioned(
                &mut conn,
                &dcid_raw,
                &scid_raw,
                &path,
                QuicVersion::V1 as u32,
                NGTCP2_CALLBACKS_VERSION as c_int,
                &callbacks,
                NGTCP2_SETTINGS_VERSION as c_int,
                &settings,
                NGTCP2_TRANSPORT_PARAMS_VERSION as c_int,
                params,
                ptr::null(),
                user_data_ptr,
            )
        };

        check_ngtcp2(rv)?;

        // Create conn_ref so TLS callbacks can recover ngtcp2_conn.
        let mut conn_ref = Box::new(ConnRef {
            inner: ngtcp2_crypto_conn_ref {
                get_conn: Some(conn_ref_get_conn_callback),
                user_data: conn as *mut c_void,
            },
        });

        // Store conn_ref on SSL. SSL_set_app_data is a macro for
        // SSL_set_ex_data(ssl, 0, data).
        unsafe {
            aws_lc_sys::SSL_set_ex_data(
                tls_session.as_ptr(),
                0,
                &mut conn_ref.inner as *mut ngtcp2_crypto_conn_ref as *mut c_void,
            );
        }

        // Set the native TLS handle.
        unsafe {
            ngtcp2_conn_set_tls_native_handle(conn, tls_session.as_void_ptr());
        }

        // Set server transport parameters on TLS before ClientHello handling.
        //
        // In aws-lc, ClientHello's quic_transport_parameters extension is
        // ignored unless SSL_set_quic_transport_params has already populated
        // hs->config->quic_transport_params. If it is empty, the client's
        // parameters are not saved and SSL_get_peer_quic_transport_params later
        // returns empty data.
        //
        // ngtcp2_crypto normally installs server parameters when HANDSHAKE keys
        // are installed, which is after ClientHello processing. Set them here
        // early so aws-lc preserves the peer parameters.
        let mut tp_buf = [0u8; 512];
        let tp_len = unsafe {
            ngtcp2_conn_encode_local_transport_params(conn, tp_buf.as_mut_ptr(), tp_buf.len())
        };
        if tp_len < 0 {
            unsafe { ngtcp2_conn_del(conn) };
            return Err(Error::from_ngtcp2(tp_len as i32));
        }
        if let Err(e) = tls_session.set_quic_transport_params(&tp_buf[..tp_len as usize]) {
            unsafe { ngtcp2_conn_del(conn) };
            return Err(e);
        }

        Ok(Self {
            inner: conn,
            user_data: user_data_box,
            _tls_session: Some(tls_session),
            _conn_ref: Some(conn_ref),
        })
    }

    /// Reads a packet.
    pub fn read_pkt(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        pkt_info: &PacketInfo,
        data: &[u8],
        ts: u64,
    ) -> Result<()> {
        let (local_sockaddr, local_len) = sockaddr_to_raw(local_addr);
        let (remote_sockaddr, remote_len) = sockaddr_to_raw(remote_addr);

        let path = ngtcp2_path {
            local: ngtcp2_addr {
                addr: &local_sockaddr as *const _ as *mut _,
                addrlen: local_len,
            },
            remote: ngtcp2_addr {
                addr: &remote_sockaddr as *const _ as *mut _,
                addrlen: remote_len,
            },
            user_data: ptr::null_mut(),
        };

        let pi = ngtcp2_pkt_info { ecn: pkt_info.ecn };

        let rv = unsafe {
            ngtcp2_conn_read_pkt_versioned(
                self.inner,
                &path,
                NGTCP2_PKT_INFO_VERSION as c_int,
                &pi,
                data.as_ptr(),
                data.len(),
                ts,
            )
        };

        check_ngtcp2(rv as c_int)
    }

    /// Writes a packet.
    pub fn write_pkt(&mut self, buf: &mut [u8], ts: u64) -> Result<(usize, PacketInfo)> {
        let mut pi = ngtcp2_pkt_info { ecn: 0 };

        // path must contain valid buffers because ngtcp2 writes output path
        // information into its addr fields.
        let mut local_addr = empty_sockaddr_storage();
        let mut remote_addr = empty_sockaddr_storage();

        let mut path = ngtcp2_path {
            local: ngtcp2_addr {
                addr: &mut local_addr as *mut _ as *mut _,
                addrlen: sockaddr_storage_len(),
            },
            remote: ngtcp2_addr {
                addr: &mut remote_addr as *mut _ as *mut _,
                addrlen: sockaddr_storage_len(),
            },
            user_data: ptr::null_mut(),
        };

        let rv = unsafe {
            ngtcp2_conn_write_pkt_versioned(
                self.inner,
                &mut path,
                NGTCP2_PKT_INFO_VERSION as c_int,
                &mut pi,
                buf.as_mut_ptr(),
                buf.len(),
                ts,
            )
        };

        if rv < 0 {
            return Err(Error::from_ngtcp2(rv as c_int));
        }

        Ok((rv as usize, PacketInfo { ecn: pi.ecn }))
    }

    /// Writes data to a stream.
    ///
    /// Writes one stream-data chunk immediately.
    ///
    /// # Returns
    ///
    /// - `Ok((pkt_written, Some(data_written)))`: a packet was produced, or
    ///   data was appended to the internal packet buffer.
    /// - `Err(StreamDataBlocked(stream_id))`: the stream is blocked by flow
    ///   control.
    /// - `Err(StreamShutWr(stream_id))`: the stream write side is shut down.
    pub fn write_stream(
        &mut self,
        buf: &mut [u8],
        stream_id: StreamId,
        data: &[u8],
        fin: bool,
        ts: u64,
    ) -> Result<(usize, Option<usize>)> {
        self.write_stream_vectored(buf, stream_id, &[data], fin, ts)
    }

    /// Writes vectored data to a stream.
    ///
    /// ngtcp2 requires the accepted stream bytes to stay valid until they are
    /// acknowledged or the stream is closed. Callers that receive vectors from
    /// nghttp3 should pass those vectors directly instead of copying them into
    /// a temporary buffer.
    ///
    /// See:
    /// - <https://nghttp2.org/ngtcp2/ngtcp2_conn_writev_stream.html>
    /// - <https://nghttp2.org/nghttp3/nghttp3_conn_add_write_offset.html>
    pub fn write_stream_vectored(
        &mut self,
        buf: &mut [u8],
        stream_id: StreamId,
        data: &[&[u8]],
        fin: bool,
        ts: u64,
    ) -> Result<(usize, Option<usize>)> {
        let mut pi = ngtcp2_pkt_info { ecn: 0 };
        let mut datalen: ngtcp2_ssize = -1;

        // path must contain valid buffers because ngtcp2 writes output path
        // information into its addr fields.
        let mut local_addr = empty_sockaddr_storage();
        let mut remote_addr = empty_sockaddr_storage();

        let mut path = ngtcp2_path {
            local: ngtcp2_addr {
                addr: &mut local_addr as *mut _ as *mut _,
                addrlen: sockaddr_storage_len(),
            },
            remote: ngtcp2_addr {
                addr: &mut remote_addr as *mut _ as *mut _,
                addrlen: sockaddr_storage_len(),
            },
            user_data: ptr::null_mut(),
        };

        let vecs = data
            .iter()
            .map(|slice| ngtcp2_vec {
                base: slice.as_ptr() as *mut _,
                len: slice.len(),
            })
            .collect::<Vec<_>>();

        let mut flags = ngtcp2_sys::NGTCP2_WRITE_STREAM_FLAG_NONE;
        if fin {
            flags |= ngtcp2_sys::NGTCP2_WRITE_STREAM_FLAG_FIN;
        }

        let rv = unsafe {
            ngtcp2_conn_writev_stream_versioned(
                self.inner,
                &mut path,
                NGTCP2_PKT_INFO_VERSION as c_int,
                &mut pi,
                buf.as_mut_ptr(),
                buf.len(),
                &mut datalen,
                flags,
                stream_id,
                vecs.as_ptr(),
                vecs.len(),
                ts,
            )
        };

        // Map selected ngtcp2 errors to typed variants for callers.
        if rv == ngtcp2_sys::NGTCP2_ERR_WRITE_MORE as ngtcp2_ssize {
            // Data was buffered, but no packet has been produced yet.
            let data_written = if datalen >= 0 {
                Some(datalen as usize)
            } else {
                None
            };
            return Ok((0, data_written));
        }

        if rv == ngtcp2_sys::NGTCP2_ERR_STREAM_DATA_BLOCKED as ngtcp2_ssize {
            return Err(Error::StreamDataBlocked(stream_id));
        }

        if rv == ngtcp2_sys::NGTCP2_ERR_STREAM_SHUT_WR as ngtcp2_ssize {
            return Err(Error::StreamShutWr(stream_id));
        }

        if rv < 0 {
            return Err(Error::from_ngtcp2(rv as c_int));
        }

        let data_written = if datalen >= 0 {
            Some(datalen as usize)
        } else {
            None
        };

        Ok((rv as usize, data_written))
    }

    /// Opens a bidirectional stream.
    pub fn open_bidi_stream(&mut self) -> Result<StreamId> {
        let mut stream_id: i64 = 0;
        let rv =
            unsafe { ngtcp2_conn_open_bidi_stream(self.inner, &mut stream_id, ptr::null_mut()) };
        check_ngtcp2(rv)?;
        Ok(stream_id)
    }

    /// Opens a unidirectional stream.
    pub fn open_uni_stream(&mut self) -> Result<StreamId> {
        let mut stream_id: i64 = 0;
        let rv =
            unsafe { ngtcp2_conn_open_uni_stream(self.inner, &mut stream_id, ptr::null_mut()) };
        check_ngtcp2(rv)?;
        Ok(stream_id)
    }

    /// Shuts down both directions of a stream.
    pub fn shutdown_stream(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        let rv = unsafe { ngtcp2_conn_shutdown_stream(self.inner, 0, stream_id, error_code) };
        check_ngtcp2(rv)
    }

    /// Shuts down the write side of a stream and sends FIN.
    pub fn shutdown_stream_write(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        let rv = unsafe { ngtcp2_conn_shutdown_stream_write(self.inner, 0, stream_id, error_code) };
        check_ngtcp2(rv)
    }

    /// Extends a stream's maximum offset.
    pub fn extend_max_stream_offset(&mut self, stream_id: StreamId, datalen: u64) -> Result<()> {
        let rv = unsafe { ngtcp2_conn_extend_max_stream_offset(self.inner, stream_id, datalen) };
        check_ngtcp2(rv)
    }

    /// Extends the connection maximum offset.
    pub fn extend_max_offset(&mut self, datalen: u64) {
        unsafe { ngtcp2_conn_extend_max_offset(self.inner, datalen) };
    }

    /// Returns the next expiry time.
    pub fn get_expiry(&self) -> u64 {
        unsafe { ngtcp2_conn_get_expiry(self.inner) }
    }

    /// Handles timeout processing.
    pub fn handle_expiry(&mut self, ts: u64) -> Result<()> {
        let rv = unsafe { ngtcp2_conn_handle_expiry(self.inner, ts) };
        check_ngtcp2(rv)
    }

    /// Returns whether the connection is in the closing period.
    pub fn is_in_closing_period(&self) -> bool {
        unsafe { ngtcp2_conn_in_closing_period(self.inner) != 0 }
    }

    /// Returns whether the connection is in the draining period.
    pub fn is_in_draining_period(&self) -> bool {
        unsafe { ngtcp2_conn_in_draining_period(self.inner) != 0 }
    }

    /// Returns whether the handshake completed.
    pub fn is_handshake_completed(&self) -> bool {
        unsafe { ngtcp2_conn_get_handshake_completed(self.inner) != 0 }
    }

    /// Sets the native TLS handle.
    ///
    /// # Safety
    /// `handle` must be a valid native TLS handle pointer.
    pub unsafe fn set_tls_native_handle(&mut self, handle: *mut c_void) {
        unsafe { ngtcp2_conn_set_tls_native_handle(self.inner, handle) };
    }

    /// Returns the native TLS handle.
    pub fn get_tls_native_handle(&self) -> *mut c_void {
        unsafe { ngtcp2_conn_get_tls_native_handle(self.inner) }
    }

    /// Sets the keep-alive timeout.
    pub fn set_keep_alive_timeout(&mut self, timeout: u64) {
        unsafe { ngtcp2_conn_set_keep_alive_timeout(self.inner, timeout) };
    }

    /// Returns the remaining connection data credit.
    pub fn get_max_data_left(&self) -> u64 {
        unsafe { ngtcp2_conn_get_max_data_left(self.inner) }
    }

    /// Returns the remaining bidirectional stream credit.
    pub fn get_streams_bidi_left(&self) -> u64 {
        unsafe { ngtcp2_conn_get_streams_bidi_left(self.inner) }
    }

    /// Returns the remaining unidirectional stream credit.
    pub fn get_streams_uni_left(&self) -> u64 {
        unsafe { ngtcp2_conn_get_streams_uni_left(self.inner) }
    }

    /// Polls received stream data.
    ///
    /// Pops one stream data event from the queue. Returns `None` when no data is
    /// available.
    pub fn poll_stream_data(&mut self) -> Option<StreamData> {
        self.user_data.stream_data_queue.pop_front()
    }

    /// Returns whether received stream data is queued.
    pub fn has_stream_data(&self) -> bool {
        !self.user_data.stream_data_queue.is_empty()
    }

    /// Returns the remote peer's `max_datagram_frame_size`.
    ///
    /// Returns the size when the remote peer supports DATAGRAM. Returns 0 when
    /// DATAGRAM is unsupported or transport parameters are not exchanged yet.
    pub fn get_remote_max_datagram_frame_size(&self) -> u64 {
        let params = unsafe { ngtcp2_conn_get_remote_transport_params(self.inner) };
        if params.is_null() {
            return 0;
        }
        unsafe { (*params).max_datagram_frame_size }
    }

    /// Returns the local `max_datagram_frame_size`.
    ///
    /// Returns the size when the local endpoint supports DATAGRAM.
    pub fn get_local_max_datagram_frame_size(&self) -> u64 {
        let params = unsafe { ngtcp2_conn_get_local_transport_params(self.inner) };
        if params.is_null() {
            return 0;
        }
        unsafe { (*params).max_datagram_frame_size }
    }

    /// Returns whether the remote peer supports DATAGRAM.
    ///
    /// Check this before sending DATAGRAM frames.
    pub fn can_send_datagram(&self) -> bool {
        self.get_remote_max_datagram_frame_size() > 0
    }

    /// Sends a DATAGRAM.
    ///
    /// Sends data in a QUIC DATAGRAM frame. DATAGRAM delivery is unreliable and
    /// unordered.
    ///
    /// # Arguments
    ///
    /// * `buf` - Output packet buffer.
    /// * `data` - Data to send.
    /// * `ts` - Timestamp in nanoseconds.
    ///
    /// # Returns
    ///
    /// * `Ok((written, accepted))` - `written` is the packet size; `accepted`
    ///   reports whether the data was accepted.
    ///
    /// # Errors
    ///
    /// Returns ERR_INVALID_STATE if the remote peer does not support DATAGRAM.
    pub fn write_datagram(
        &mut self,
        buf: &mut [u8],
        data: &[u8],
        ts: u64,
    ) -> Result<(usize, bool)> {
        // Check whether the remote peer supports DATAGRAM.
        if !self.can_send_datagram() {
            return Err(Error::Ngtcp2(
                "ERR_INVALID_STATE: remote peer does not support DATAGRAM".to_string(),
                NGTCP2_ERR_INVALID_STATE,
            ));
        }

        // Ensure inner is not null.
        if self.inner.is_null() {
            return Err(Error::Internal("connection is null".to_string()));
        }

        let mut pi = ngtcp2_pkt_info { ecn: 0 };
        let mut accepted: c_int = 0;

        let vec = ngtcp2_vec {
            base: data.as_ptr() as *mut _,
            len: data.len(),
        };

        // Pass NULL for path when path information is not needed. A zeroed
        // ngtcp2_path leaves internal pointers NULL and can segfault.
        let rv = unsafe {
            ngtcp2_conn_writev_datagram_versioned(
                self.inner,
                ptr::null_mut(), // path is not needed
                NGTCP2_PKT_INFO_VERSION as c_int,
                &mut pi,
                buf.as_mut_ptr(),
                buf.len(),
                &mut accepted,
                NGTCP2_WRITE_DATAGRAM_FLAG_NONE,
                0, // dgram_id
                &vec,
                1,
                ts,
            )
        };

        if rv < 0 {
            return Err(Error::from_ngtcp2(rv as c_int));
        }

        Ok((rv as usize, accepted != 0))
    }

    /// Polls a received DATAGRAM.
    ///
    /// Pops one DATAGRAM from the queue. Returns `None` when no data is
    /// available.
    pub fn poll_datagram(&mut self) -> Option<Datagram> {
        self.user_data.datagram_queue.pop_front()
    }

    /// Returns whether a received DATAGRAM is queued.
    pub fn has_datagram(&self) -> bool {
        !self.user_data.datagram_queue.is_empty()
    }

    /// Writes a CONNECTION_CLOSE packet with a transport error.
    ///
    /// Used to close the QUIC connection. Generates a CONNECTION_CLOSE frame
    /// carrying a transport error code.
    ///
    /// # Arguments
    ///
    /// * `buf` - Output buffer.
    /// * `error_code` - Transport error code, for example `NGTCP2_NO_ERROR`.
    /// * `reason` - Error reason; may be empty.
    /// * `ts` - Timestamp in nanoseconds.
    pub fn write_connection_close(
        &mut self,
        buf: &mut [u8],
        error_code: u64,
        reason: &[u8],
        ts: u64,
    ) -> Result<usize> {
        let mut ccerr: ngtcp2_ccerr = unsafe { std::mem::zeroed() };
        unsafe {
            ngtcp2_ccerr_default(&mut ccerr);
            ngtcp2_ccerr_set_transport_error(&mut ccerr, error_code, reason.as_ptr(), reason.len());
        }

        let mut pi = ngtcp2_pkt_info { ecn: 0 };

        let rv = unsafe {
            ngtcp2_conn_write_connection_close_versioned(
                self.inner,
                ptr::null_mut(),
                NGTCP2_PKT_INFO_VERSION as c_int,
                &mut pi,
                buf.as_mut_ptr(),
                buf.len(),
                &ccerr,
                ts,
            )
        };

        if rv < 0 {
            return Err(Error::from_ngtcp2(rv as c_int));
        }

        Ok(rv as usize)
    }

    /// Writes a CONNECTION_CLOSE packet with an application error.
    ///
    /// Used when closing the connection with an application-layer error such as
    /// HTTP/3.
    ///
    /// # Arguments
    ///
    /// * `buf` - Output buffer.
    /// * `error_code` - Application error code.
    /// * `reason` - Error reason; may be empty.
    /// * `ts` - Timestamp in nanoseconds.
    pub fn write_connection_close_app(
        &mut self,
        buf: &mut [u8],
        error_code: u64,
        reason: &[u8],
        ts: u64,
    ) -> Result<usize> {
        let mut ccerr: ngtcp2_ccerr = unsafe { std::mem::zeroed() };
        unsafe {
            ngtcp2_ccerr_default(&mut ccerr);
            ngtcp2_ccerr_set_application_error(
                &mut ccerr,
                error_code,
                reason.as_ptr(),
                reason.len(),
            );
        }

        let mut pi = ngtcp2_pkt_info { ecn: 0 };

        let rv = unsafe {
            ngtcp2_conn_write_connection_close_versioned(
                self.inner,
                ptr::null_mut(),
                NGTCP2_PKT_INFO_VERSION as c_int,
                &mut pi,
                buf.as_mut_ptr(),
                buf.len(),
                &ccerr,
                ts,
            )
        };

        if rv < 0 {
            return Err(Error::from_ngtcp2(rv as c_int));
        }

        Ok(rv as usize)
    }

    /// Returns the inner pointer.
    pub fn as_ptr(&self) -> *mut ngtcp2_conn {
        self.inner
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            unsafe { ngtcp2_conn_del(self.inner) };
        }
    }
}

/// Converts `ConnectionId` to `ngtcp2_cid`.
fn cid_to_raw(cid: &ConnectionId) -> ngtcp2_cid {
    let mut raw = ngtcp2_cid {
        datalen: cid.len(),
        data: [0u8; 20],
    };
    raw.data[..cid.len()].copy_from_slice(cid.as_bytes());
    raw
}

fn empty_sockaddr_storage() -> RawSockAddrStorage {
    unsafe { std::mem::zeroed() }
}

fn sockaddr_storage_len() -> ngtcp2_socklen {
    std::mem::size_of::<RawSockAddrStorage>() as ngtcp2_socklen
}

/// Converts `SocketAddr` to the platform sockaddr storage used by ngtcp2.
#[cfg(not(windows))]
fn sockaddr_to_raw(addr: &SocketAddr) -> (RawSockAddrStorage, ngtcp2_socklen) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    match addr {
        SocketAddr::V4(v4) => {
            let sin: &mut libc::sockaddr_in =
                unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as ngtcp2_socklen,
            )
        }
        SocketAddr::V6(v6) => {
            let sin6: &mut libc::sockaddr_in6 =
                unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_scope_id = v6.scope_id();
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as ngtcp2_socklen,
            )
        }
    }
}

/// Converts `SocketAddr` to the WinSock sockaddr storage used by ngtcp2.
#[cfg(windows)]
fn sockaddr_to_raw(addr: &SocketAddr) -> (RawSockAddrStorage, ngtcp2_socklen) {
    let mut storage = empty_sockaddr_storage();

    match addr {
        SocketAddr::V4(v4) => {
            let sin: &mut SOCKADDR_IN =
                unsafe { &mut *(&mut storage as *mut _ as *mut SOCKADDR_IN) };
            sin.sin_family = AF_INET;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr = IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
            };

            (
                storage,
                std::mem::size_of::<SOCKADDR_IN>() as ngtcp2_socklen,
            )
        }
        SocketAddr::V6(v6) => {
            let sin6: &mut SOCKADDR_IN6 =
                unsafe { &mut *(&mut storage as *mut _ as *mut SOCKADDR_IN6) };
            sin6.sin6_family = AF_INET6;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_addr = IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: v6.ip().octets(),
                },
            };
            sin6.Anonymous = SOCKADDR_IN6_0 {
                sin6_scope_id: v6.scope_id(),
            };

            (
                storage,
                std::mem::size_of::<SOCKADDR_IN6>() as ngtcp2_socklen,
            )
        }
    }
}

/// Creates client callbacks.
fn create_client_callbacks() -> ngtcp2_callbacks {
    let mut callbacks: ngtcp2_callbacks = unsafe { std::mem::zeroed() };

    // Required ngtcp2_crypto_* callbacks.
    callbacks.client_initial = Some(ngtcp2_crypto_client_initial_cb);
    callbacks.recv_crypto_data = Some(ngtcp2_crypto_recv_crypto_data_cb);
    callbacks.encrypt = Some(ngtcp2_crypto_encrypt_cb);
    callbacks.decrypt = Some(ngtcp2_crypto_decrypt_cb);
    callbacks.hp_mask = Some(ngtcp2_crypto_hp_mask_cb);
    callbacks.recv_retry = Some(ngtcp2_crypto_recv_retry_cb);
    callbacks.update_key = Some(ngtcp2_crypto_update_key_cb);
    callbacks.delete_crypto_aead_ctx = Some(ngtcp2_crypto_delete_crypto_aead_ctx_cb);
    callbacks.delete_crypto_cipher_ctx = Some(ngtcp2_crypto_delete_crypto_cipher_ctx_cb);
    callbacks.get_path_challenge_data = Some(ngtcp2_crypto_get_path_challenge_data_cb);
    callbacks.version_negotiation = Some(ngtcp2_crypto_version_negotiation_cb);

    // Stream data receive callback.
    callbacks.recv_stream_data = Some(recv_stream_data_callback);

    // DATAGRAM receive callback.
    callbacks.recv_datagram = Some(recv_datagram_callback);

    // Other required callbacks.
    callbacks.rand = Some(rand_callback);
    callbacks.get_new_connection_id = Some(get_new_connection_id_callback);

    callbacks
}

/// Creates server callbacks.
fn create_server_callbacks() -> ngtcp2_callbacks {
    let mut callbacks: ngtcp2_callbacks = unsafe { std::mem::zeroed() };

    // Required ngtcp2_crypto_* callbacks.
    callbacks.recv_client_initial = Some(ngtcp2_crypto_recv_client_initial_cb);
    callbacks.recv_crypto_data = Some(ngtcp2_crypto_recv_crypto_data_cb);
    callbacks.encrypt = Some(ngtcp2_crypto_encrypt_cb);
    callbacks.decrypt = Some(ngtcp2_crypto_decrypt_cb);
    callbacks.hp_mask = Some(ngtcp2_crypto_hp_mask_cb);
    callbacks.update_key = Some(ngtcp2_crypto_update_key_cb);
    callbacks.delete_crypto_aead_ctx = Some(ngtcp2_crypto_delete_crypto_aead_ctx_cb);
    callbacks.delete_crypto_cipher_ctx = Some(ngtcp2_crypto_delete_crypto_cipher_ctx_cb);
    callbacks.get_path_challenge_data = Some(ngtcp2_crypto_get_path_challenge_data_cb);
    callbacks.version_negotiation = Some(ngtcp2_crypto_version_negotiation_cb);

    // Stream data receive callback.
    callbacks.recv_stream_data = Some(recv_stream_data_callback);

    // DATAGRAM receive callback.
    callbacks.recv_datagram = Some(recv_datagram_callback);

    // Other required callbacks.
    callbacks.rand = Some(rand_callback);
    callbacks.get_new_connection_id = Some(get_new_connection_id_callback);

    callbacks
}

/// Randomness callback.
unsafe extern "C" fn rand_callback(buf: *mut u8, buflen: usize, _rand_ctx: *const ngtcp2_rand_ctx) {
    if buf.is_null() || buflen == 0 {
        return;
    }

    // SAFETY: buf is a non-null caller-provided buffer with buflen bytes.
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, buflen) };
    let _ = aws_lc_rs::rand::fill(slice);
}

/// New connection ID callback.
unsafe extern "C" fn get_new_connection_id_callback(
    _conn: *mut ngtcp2_conn,
    cid: *mut ngtcp2_cid,
    token: *mut u8,
    cidlen: usize,
    _user_data: *mut c_void,
) -> c_int {
    if cid.is_null() || token.is_null() || cidlen > NGTCP2_MAX_CIDLEN as usize {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    // SAFETY: cid and token are non-null caller-provided output buffers.
    unsafe {
        // Generate the connection ID.
        let cid_slice = std::slice::from_raw_parts_mut((*cid).data.as_mut_ptr(), cidlen);
        if aws_lc_rs::rand::fill(cid_slice).is_err() {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        (*cid).datalen = cidlen;

        // Generate the stateless reset token.
        let token_slice =
            std::slice::from_raw_parts_mut(token, NGTCP2_STATELESS_RESET_TOKENLEN as usize);
        if aws_lc_rs::rand::fill(token_slice).is_err() {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    0
}

/// Callback that extracts `ngtcp2_conn` from conn_ref.
///
/// Called by TLS callbacks such as `add_handshake_data`. `conn_ref.user_data`
/// stores the `ngtcp2_conn` pointer.
unsafe extern "C" fn conn_ref_get_conn_callback(
    conn_ref: *mut ngtcp2_crypto_conn_ref,
) -> *mut ngtcp2_conn {
    // SAFETY: conn_ref is valid and user_data stores the ngtcp2_conn pointer.
    unsafe { (*conn_ref).user_data as *mut ngtcp2_conn }
}

/// Stream data receive callback.
///
/// Called when data is received on a QUIC stream. Copies the bytes into the
/// user-data queue.
unsafe extern "C" fn recv_stream_data_callback(
    _conn: *mut ngtcp2_conn,
    _flags: u32,
    stream_id: i64,
    _offset: u64,
    data: *const u8,
    datalen: usize,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    if user_data.is_null() || (data.is_null() && datalen > 0) {
        return 0;
    }

    unsafe {
        let conn_user_data = &mut *(user_data as *mut ConnectionUserData);

        // Copy the data into the queue.
        let data_slice = if datalen > 0 {
            std::slice::from_raw_parts(data, datalen).to_vec()
        } else {
            Vec::new()
        };

        let fin = (_flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;

        conn_user_data.stream_data_queue.push_back(StreamData {
            stream_id,
            data: data_slice,
            fin,
        });
    }

    0
}

/// DATAGRAM receive callback.
///
/// Called when a QUIC DATAGRAM frame is received. Copies the bytes into the
/// user-data queue.
unsafe extern "C" fn recv_datagram_callback(
    _conn: *mut ngtcp2_conn,
    _flags: u32,
    data: *const u8,
    datalen: usize,
    user_data: *mut c_void,
) -> c_int {
    if user_data.is_null() || (data.is_null() && datalen > 0) {
        return 0;
    }

    unsafe {
        let conn_user_data = &mut *(user_data as *mut ConnectionUserData);

        // Copy the data into the queue.
        let data_slice = if datalen > 0 {
            std::slice::from_raw_parts(data, datalen).to_vec()
        } else {
            Vec::new()
        };

        conn_user_data
            .datagram_queue
            .push_back(Datagram { data: data_slice });
    }

    0
}
