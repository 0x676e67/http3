//! HTTP/3 client implementation.

use std::net::SocketAddr;
use std::time::Duration;

use ngtcp2::{
    Connection, ConnectionId, Error, Header, Http3Connection, Http3Event, Http3SettingsExt,
    PacketInfo, Result, StreamId, TlsContext, TransportParamsExt, nghttp3_settings,
    ngtcp2_transport_params,
};

use crate::{Socket, timestamp};

/// HTTP/3 client.
pub struct Client {
    socket: Socket,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    // TLS context kept alive for SSL_CTX ownership.
    _tls_ctx: TlsContext,
    // QUIC connection.
    conn: Connection,
    // HTTP/3 connection.
    h3_conn: Http3Connection,
    // Receive buffer.
    recv_buf: Vec<u8>,
    // Send buffer.
    send_buf: Vec<u8>,
    // Whether control streams are already bound.
    control_streams_bound: bool,
}

// SAFETY: Client is driven through &mut self, so moving it to another task keeps
// exclusive access to the underlying ngtcp2/nghttp3 state machines.
unsafe impl Send for Client {}

impl Client {
    /// Creates a new client.
    ///
    /// # Arguments
    ///
    /// * `remote_addr` - Peer address.
    /// * `server_name` - Server name for SNI.
    /// * `transport_params` - QUIC transport parameters; defaults when `None`.
    /// * `h3_settings` - HTTP/3 settings; defaults when `None`.
    pub async fn connect(
        remote_addr: SocketAddr,
        server_name: &str,
        transport_params: Option<ngtcp2_transport_params>,
        h3_settings: Option<nghttp3_settings>,
    ) -> Result<Self> {
        Self::connect_with_options(
            remote_addr,
            server_name,
            transport_params,
            h3_settings,
            true,
        )
        .await
    }

    /// Creates a new client without certificate verification.
    ///
    /// Used with self-signed certificates in tests.
    ///
    /// # Arguments
    ///
    /// * `remote_addr` - Peer address.
    /// * `server_name` - Server name for SNI.
    /// * `transport_params` - QUIC transport parameters; defaults when `None`.
    /// * `h3_settings` - HTTP/3 settings; defaults when `None`.
    pub async fn connect_insecure(
        remote_addr: SocketAddr,
        server_name: &str,
        transport_params: Option<ngtcp2_transport_params>,
        h3_settings: Option<nghttp3_settings>,
    ) -> Result<Self> {
        Self::connect_with_options(
            remote_addr,
            server_name,
            transport_params,
            h3_settings,
            false,
        )
        .await
    }

    /// Creates a new client without certificate verification and with defaults.
    ///
    /// Convenience API for tests. Uses default transport parameters and HTTP/3
    /// settings. The result is usable inside `tokio::spawn` because it is
    /// `Send + 'static`.
    ///
    /// # Arguments
    ///
    /// * `remote_addr` - Peer address.
    /// * `server_name` - Server name for SNI.
    pub async fn connect_insecure_default(
        remote_addr: SocketAddr,
        server_name: &str,
    ) -> Result<Self> {
        Self::connect_internal(remote_addr, server_name, false).await
    }

    /// Internal connection helper using default settings.
    async fn connect_internal(
        remote_addr: SocketAddr,
        server_name: &str,
        verify_peer: bool,
    ) -> Result<Self> {
        // Bind the local UDP socket.
        let local_addr: SocketAddr = if remote_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let socket = Socket::bind(local_addr)
            .await
            .map_err(|e| Error::Internal(format!("failed to bind socket: {}", e)))?;

        let local_addr = socket.local_addr();

        // Default transport parameters.
        let params = ngtcp2_transport_params::default_params();

        // Default HTTP/3 settings.
        let h3_settings = nghttp3_settings::default_settings();

        // Create the TLS context and session.
        let tls_ctx = TlsContext::new_client_with_options(&[b"h3"], verify_peer)?;
        let tls_session = tls_ctx.create_session()?;

        // Generate connection IDs.
        let dcid = ConnectionId::random(16)
            .ok_or(Error::Internal("failed to generate dcid".to_string()))?;
        let scid = ConnectionId::random(16)
            .ok_or(Error::Internal("failed to generate scid".to_string()))?;

        // Timestamp.
        let ts = timestamp();

        // Create the QUIC connection.
        let conn = Connection::client_new(
            &dcid,
            &scid,
            local_addr,
            remote_addr,
            server_name,
            tls_session,
            &params,
            ts,
        )?;

        // Create the HTTP/3 connection.
        let h3_conn = Http3Connection::client_new(&h3_settings)?;

        Ok(Self {
            socket,
            local_addr,
            remote_addr,
            _tls_ctx: tls_ctx,
            conn,
            h3_conn,
            recv_buf: vec![0u8; 65535],
            send_buf: vec![0u8; 1350],
            control_streams_bound: false,
        })
    }

    /// Creates a new client with options.
    ///
    /// # Arguments
    ///
    /// * `remote_addr` - Peer address.
    /// * `server_name` - Server name for SNI.
    /// * `transport_params` - QUIC transport parameters; defaults when `None`.
    /// * `h3_settings` - HTTP/3 settings; defaults when `None`.
    /// * `verify_peer` - Whether to verify the server certificate.
    async fn connect_with_options(
        remote_addr: SocketAddr,
        server_name: &str,
        transport_params: Option<ngtcp2_transport_params>,
        h3_settings: Option<nghttp3_settings>,
        verify_peer: bool,
    ) -> Result<Self> {
        // Bind the local UDP socket.
        let local_addr: SocketAddr = if remote_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let socket = Socket::bind(local_addr)
            .await
            .map_err(|e| Error::Internal(format!("failed to bind socket: {}", e)))?;

        let local_addr = socket.local_addr();

        // Transport parameters.
        let params = transport_params.unwrap_or_else(ngtcp2_transport_params::default_params);

        // HTTP/3 settings.
        let h3_settings = h3_settings.unwrap_or_else(nghttp3_settings::default_settings);

        // Create the TLS context and session.
        let tls_ctx = TlsContext::new_client_with_options(&[b"h3"], verify_peer)?;
        let tls_session = tls_ctx.create_session()?;

        // Generate connection IDs.
        let dcid = ConnectionId::random(16)
            .ok_or(Error::Internal("failed to generate dcid".to_string()))?;
        let scid = ConnectionId::random(16)
            .ok_or(Error::Internal("failed to generate scid".to_string()))?;

        // Timestamp.
        let ts = timestamp();

        // Create the QUIC connection.
        let conn = Connection::client_new(
            &dcid,
            &scid,
            local_addr,
            remote_addr,
            server_name,
            tls_session,
            &params,
            ts,
        )?;

        // Create the HTTP/3 connection.
        let h3_conn = Http3Connection::client_new(&h3_settings)?;

        Ok(Self {
            socket,
            local_addr,
            remote_addr,
            _tls_ctx: tls_ctx,
            conn,
            h3_conn,
            recv_buf: vec![0u8; 65535],
            send_buf: vec![0u8; 1350],
            control_streams_bound: false,
        })
    }

    /// Returns the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the remote address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Sends an HTTP/3 request.
    pub fn send_request(&mut self, headers: &[Header]) -> Result<StreamId> {
        // Complete the handshake.
        if !self.conn.is_handshake_completed() {
            return Err(Error::Internal("handshake not completed".to_string()));
        }

        // Bind control streams once.
        if !self.control_streams_bound {
            self.bind_control_streams()?;
        }

        // Open a QUIC stream.
        let stream_id = self.conn.open_bidi_stream()?;

        // Submit the HTTP/3 request.
        self.h3_conn.submit_request(stream_id, headers)?;

        Ok(stream_id)
    }

    /// Sends an HTTP/3 request with a body.
    ///
    /// The body is queued as one buffer. For large or streaming bodies, call
    /// `send_request_streaming()` first and then use `send_body()`.
    ///
    /// # Arguments
    ///
    /// * `headers` - Request headers.
    /// * `body` - Request body.
    pub fn send_request_with_body(
        &mut self,
        headers: &[Header],
        body: Vec<u8>,
    ) -> Result<StreamId> {
        // Complete the handshake.
        if !self.conn.is_handshake_completed() {
            return Err(Error::Internal("handshake not completed".to_string()));
        }

        // Bind control streams once.
        if !self.control_streams_bound {
            self.bind_control_streams()?;
        }

        // Open a QUIC stream.
        let stream_id = self.conn.open_bidi_stream()?;

        // Submit the HTTP/3 request with a body.
        self.h3_conn
            .submit_request_with_body(stream_id, headers, body)?;

        Ok(stream_id)
    }

    /// Starts an HTTP/3 request for streaming upload.
    ///
    /// Use together with `send_body()`. This sends headers first; body bytes
    /// are sent later through `send_body()`.
    ///
    /// # Arguments
    ///
    /// * `headers` - Request headers.
    pub fn send_request_streaming(&mut self, headers: &[Header]) -> Result<StreamId> {
        // Complete the handshake.
        if !self.conn.is_handshake_completed() {
            return Err(Error::Internal("handshake not completed".to_string()));
        }

        // Bind control streams once.
        if !self.control_streams_bound {
            self.bind_control_streams()?;
        }

        // Open a QUIC stream.
        let stream_id = self.conn.open_bidi_stream()?;

        // Start the streaming request.
        self.h3_conn.submit_request_streaming(stream_id, headers)?;

        Ok(stream_id)
    }

    /// Sends additional request body data.
    ///
    /// Sends body data for a request started with `send_request_streaming()`.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - Stream ID.
    /// * `data` - Data to send.
    /// * `fin` - Whether to finish the stream.
    pub async fn send_body(&mut self, stream_id: StreamId, data: &[u8], fin: bool) -> Result<()> {
        self.h3_conn.send_request_body(stream_id, data, fin)?;
        self.flush().await?;
        Ok(())
    }

    /// Binds control streams.
    fn bind_control_streams(&mut self) -> Result<()> {
        // Control stream.
        let ctrl_stream_id = self.conn.open_uni_stream()?;
        self.h3_conn.bind_control_stream(ctrl_stream_id)?;

        // QPACK encoder stream.
        let qpack_enc_stream_id = self.conn.open_uni_stream()?;

        // QPACK decoder stream.
        let qpack_dec_stream_id = self.conn.open_uni_stream()?;

        self.h3_conn
            .bind_qpack_streams(qpack_enc_stream_id, qpack_dec_stream_id)?;

        self.control_streams_bound = true;
        Ok(())
    }

    /// Polls the next event.
    pub fn poll(&mut self) -> Option<Http3Event> {
        self.h3_conn.poll_event()
    }

    /// Runs the event loop until the handshake completes.
    pub async fn handshake(&mut self) -> Result<()> {
        let timeout = Duration::from_secs(30);
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            // Flush outgoing data.
            self.flush().await?;

            // Check whether the handshake completed.
            if self.conn.is_handshake_completed() {
                return Ok(());
            }

            // Calculate timeout.
            let expiry = self.conn.get_expiry();
            let now = timestamp();
            let timer_duration = if expiry > now {
                Duration::from_nanos(expiry - now)
            } else {
                Duration::from_millis(1)
            };

            tokio::select! {
                // Process incoming data.
                result = self.socket.recv_from(&mut self.recv_buf) => {
                    match result {
                        Ok((len, from)) => {
                            if from == self.remote_addr {
                                let data = self.recv_buf[..len].to_vec();
                                self.handle_recv(&data).await?;
                            }
                        }
                        Err(e) => {
                            return Err(Error::Internal(format!("recv error: {}", e)));
                        }
                    }
                }

                // Timeout.
                _ = tokio::time::sleep(timer_duration) => {
                    let ts = timestamp();
                    self.conn.handle_expiry(ts)?;
                }

                // Overall timeout.
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(Error::Internal("handshake timeout".to_string()));
                }
            }
        }
    }

    /// Runs the event loop.
    pub async fn run(&mut self) -> Result<()> {
        loop {
            // Flush outgoing data.
            self.flush().await?;

            // Stop once the connection is closed.
            if self.conn.is_in_closing_period() || self.conn.is_in_draining_period() {
                return Ok(());
            }

            // Calculate timeout.
            let expiry = self.conn.get_expiry();
            let now = timestamp();
            let timer_duration = if expiry > now {
                Duration::from_nanos(expiry - now)
            } else {
                Duration::from_millis(1)
            };

            tokio::select! {
                // Process incoming data.
                result = self.socket.recv_from(&mut self.recv_buf) => {
                    match result {
                        Ok((len, from)) => {
                            if from == self.remote_addr {
                                let data = self.recv_buf[..len].to_vec();
                                self.handle_recv(&data).await?;
                            }
                        }
                        Err(e) => {
                            return Err(Error::Internal(format!("recv error: {}", e)));
                        }
                    }
                }

                // Timeout.
                _ = tokio::time::sleep(timer_duration) => {
                    let ts = timestamp();
                    self.conn.handle_expiry(ts)?;
                }
            }
        }
    }

    /// Handles received data.
    async fn handle_recv(&mut self, data: &[u8]) -> Result<()> {
        let ts = timestamp();
        let pkt_info = PacketInfo::default();

        // Process the QUIC packet.
        self.conn
            .read_pkt(&self.local_addr, &self.remote_addr, &pkt_info, data, ts)?;

        // Process HTTP/3 after the handshake completes.
        if self.conn.is_handshake_completed() && !self.control_streams_bound {
            self.bind_control_streams()?;
        }

        // Pass received stream data to HTTP/3. Following the ngtcp2 examples,
        // pass data and fin together.
        while let Some(stream_data) = self.conn.poll_stream_data() {
            let consumed = self.h3_conn.read_stream(
                stream_data.stream_id,
                &stream_data.data,
                stream_data.fin,
                ts,
            )?;

            if consumed > 0 {
                self.conn
                    .extend_max_stream_offset(stream_data.stream_id, consumed as u64)?;
                self.conn.extend_max_offset(consumed as u64);
            }
        }

        Ok(())
    }

    /// Flushes outgoing data.
    pub async fn flush(&mut self) -> Result<()> {
        let ts = timestamp();

        // Write HTTP/3 stream data after the handshake completes.
        if self.conn.is_handshake_completed() && self.control_streams_bound {
            // Write HTTP/3 stream data and collect packets.
            let packets = self.write_h3_streams(ts)?;

            // Send collected packets.
            for pkt in packets {
                self.socket
                    .send_to(&pkt, self.remote_addr)
                    .await
                    .map_err(|e| Error::Internal(format!("send error: {}", e)))?;
            }
        }

        // Send remaining QUIC packets.
        loop {
            // Write a QUIC packet.
            let (written, _pkt_info) = self.conn.write_pkt(&mut self.send_buf, ts)?;

            if written == 0 {
                break;
            }

            // Send over UDP.
            self.socket
                .send_to(&self.send_buf[..written], self.remote_addr)
                .await
                .map_err(|e| Error::Internal(format!("send error: {}", e)))?;
        }

        Ok(())
    }

    /// Receives and processes data once.
    ///
    /// Receives from the socket and advances QUIC/HTTP/3 processing. Returns
    /// when no data arrives within the given timeout.
    pub async fn recv(&mut self, timeout: Duration) -> Result<()> {
        tokio::select! {
            result = self.socket.recv_from(&mut self.recv_buf) => {
                match result {
                    Ok((len, from)) => {
                        if from == self.remote_addr {
                            let data = self.recv_buf[..len].to_vec();
                            self.handle_recv(&data).await?;
                        }
                    }
                    Err(e) => {
                        return Err(Error::Internal(format!("recv error: {}", e)));
                    }
                }
            }

            _ = tokio::time::sleep(timeout) => {
                // Timeout: nothing to do.
            }
        }

        // Timeout handling. After handle_recv passes a new timestamp to ngtcp2,
        // calling handle_expiry with an older timestamp can violate ngtcp2's
        // monotonicity assertion, so get a fresh timestamp after select!.
        let ts = timestamp();
        let expiry = self.conn.get_expiry();
        if expiry <= ts {
            self.conn.handle_expiry(ts)?;
        }

        Ok(())
    }

    /// Writes HTTP/3 stream data and collects packets synchronously.
    ///
    /// Follows ngtcp2 examples and uses NGTCP2_WRITE_STREAM_FLAG_MORE to
    /// coalesce multiple stream-data writes into one packet.
    fn write_h3_streams(&mut self, ts: u64) -> Result<Vec<Vec<u8>>> {
        use ngtcp2::nghttp3_vec;

        let mut packets = Vec::new();

        // Get data to write from HTTP/3.
        let mut vecs = [nghttp3_vec {
            base: std::ptr::null_mut(),
            len: 0,
        }; 16];

        while let Ok((stream_id, fin, count)) = self.h3_conn.write_stream(&mut vecs) {
            if count == 0 {
                break;
            }

            // Copy from nghttp3_vec to avoid pointer lifetime issues.
            let mut h3_data = Vec::new();
            for vec in vecs.iter().take(count) {
                if vec.len == 0 || vec.base.is_null() {
                    continue;
                }
                let data = unsafe { std::slice::from_raw_parts(vec.base as *const u8, vec.len) };
                h3_data.extend_from_slice(data);
            }

            // Even empty data must be sent when FIN is set.
            if h3_data.is_empty() && !fin {
                continue;
            }

            // Write to the QUIC stream and handle selected errors following the
            // ngtcp2 examples.
            let result = self
                .conn
                .write_stream(&mut self.send_buf, stream_id, &h3_data, fin, ts);

            match result {
                Ok((pkt_written, data_written)) => {
                    // Copy and collect the packet.
                    if pkt_written > 0 {
                        packets.push(self.send_buf[..pkt_written].to_vec());
                    }

                    // Tell nghttp3 how many bytes were written.
                    if let Some(dw) = data_written
                        && dw > 0
                    {
                        self.h3_conn.add_write_offset(stream_id, dw)?;
                    }
                }
                Err(Error::StreamDataBlocked(_)) => {
                    // ngtcp2 examples: call nghttp3_conn_block_stream and
                    // continue.
                    self.h3_conn.block_stream(stream_id);
                    continue;
                }
                Err(Error::StreamShutWr(_)) => {
                    // ngtcp2 examples: call nghttp3_conn_shutdown_stream_write
                    // and continue.
                    self.h3_conn.shutdown_stream_write(stream_id);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(packets)
    }
}
