//! WebTransport session implementation.
//!
//! Manages WebTransport sessions over HTTP/3.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use ngtcp2::{
    Connection, ConnectionId, Error, Header, Http3Connection, Http3Event, Http3SettingsExt,
    PacketInfo, Result, SessionId, StreamId, TlsContext, TransportParamsExt, nghttp3_settings,
    ngtcp2_transport_params, varint,
};

use crate::{Socket, timestamp};

/// WebTransport client session.
pub struct ClientWebTransportSession {
    socket: Socket,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    // TLS context kept alive for SSL_CTX ownership.
    _tls_ctx: TlsContext,
    // QUIC connection.
    conn: Connection,
    // HTTP/3 connection.
    h3_conn: Http3Connection,
    // WebTransport session ID.
    session_id: Option<SessionId>,
    // Receive buffer.
    recv_buf: Vec<u8>,
    // Send buffer.
    send_buf: Vec<u8>,
    // Whether control streams are already bound.
    control_streams_bound: bool,
}

// SAFETY: All fields in ClientWebTransportSession are Send/Sync.
unsafe impl Send for ClientWebTransportSession {}
unsafe impl Sync for ClientWebTransportSession {}

impl ClientWebTransportSession {
    /// Creates a WebTransport session.
    ///
    /// # Arguments
    ///
    /// * `remote_addr` - Peer address.
    /// * `server_name` - Server name for SNI.
    /// * `path` - WebTransport path, for example `"/webtransport"`.
    pub async fn connect(remote_addr: SocketAddr, server_name: &str, _path: &str) -> Result<Self> {
        Self::connect_with_options(remote_addr, server_name, _path, true).await
    }

    /// Creates a WebTransport session without certificate verification.
    ///
    /// Used with self-signed certificates in tests.
    ///
    /// # Arguments
    ///
    /// * `remote_addr` - Peer address.
    /// * `server_name` - Server name for SNI.
    /// * `path` - WebTransport path, for example `"/webtransport"`.
    pub async fn connect_insecure(
        remote_addr: SocketAddr,
        server_name: &str,
        _path: &str,
    ) -> Result<Self> {
        Self::connect_with_options(remote_addr, server_name, _path, false).await
    }

    /// Creates a WebTransport session with options.
    ///
    /// # Arguments
    ///
    /// * `remote_addr` - Peer address.
    /// * `server_name` - Server name for SNI.
    /// * `path` - WebTransport path, for example `"/webtransport"`.
    /// * `verify_peer` - Whether to verify the server certificate.
    async fn connect_with_options(
        remote_addr: SocketAddr,
        server_name: &str,
        _path: &str,
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

        // Transport parameters for WebTransport.
        let params = ngtcp2_transport_params::default_params().with_datagram(65535);

        // HTTP/3 settings for WebTransport.
        let h3_settings = nghttp3_settings::default_settings().with_webtransport();

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
            session_id: None,
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

    /// Returns the session ID.
    pub fn session_id(&self) -> Option<SessionId> {
        self.session_id
    }

    /// Completes the handshake.
    pub async fn handshake(&mut self) -> Result<()> {
        let timeout = Duration::from_secs(30);
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            // Flush outgoing data.
            self.flush().await?;

            // Check whether the handshake completed.
            if self.conn.is_handshake_completed() {
                // Bind control streams.
                if !self.control_streams_bound {
                    self.bind_control_streams()?;
                }
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
                result = self.socket.recv_from(&mut self.recv_buf) => {
                    match result {
                        Ok((len, from)) => {
                            if from == self.remote_addr {
                                let data = self.recv_buf[..len].to_vec();
                                self.handle_recv(&data)?;
                            }
                        }
                        Err(e) => {
                            return Err(Error::Internal(format!("recv error: {}", e)));
                        }
                    }
                }

                _ = tokio::time::sleep(timer_duration) => {
                    let ts = timestamp();
                    self.conn.handle_expiry(ts)?;
                }

                _ = tokio::time::sleep_until(deadline) => {
                    return Err(Error::Internal("handshake timeout".to_string()));
                }
            }
        }
    }

    /// Starts the WebTransport session.
    ///
    /// # Arguments
    ///
    /// * `authority` - Host name, for example `"localhost:4433"`.
    /// * `path` - WebTransport path, for example `"/webtransport"`.
    pub async fn open_session(&mut self, authority: &str, path: &str) -> Result<SessionId> {
        // Complete the handshake.
        if !self.conn.is_handshake_completed() {
            return Err(Error::Internal("handshake not completed".to_string()));
        }

        // Run send/receive loops to complete SETTINGS exchange. nghttp3 does
        // not allow WebTransport requests until peer SETTINGS are received.
        let timeout = Duration::from_secs(5);
        let deadline = tokio::time::Instant::now() + timeout;

        let headers = vec![
            Header::method("CONNECT"),
            Header::new(b":protocol", b"webtransport"),
            Header::scheme("https"),
            Header::authority(authority),
            Header::path(path),
        ];

        // Open one stream and reuse it. Opening a new stream after every retry
        // would leak unused streams.
        let mut stream_id = None;

        loop {
            // Check connection state.
            if self.conn.is_in_draining_period() {
                return Err(Error::Ngtcp2("ERR_DRAINING".to_string(), -224));
            }
            if self.conn.is_in_closing_period() {
                return Err(Error::Internal("connection closing".to_string()));
            }

            // Flush outgoing data.
            self.flush().await?;

            // Open the stream if it is not open yet.
            if stream_id.is_none() {
                stream_id = self.conn.open_bidi_stream().ok();
            }

            // Submit the WebTransport CONNECT request.
            if let Some(sid) = stream_id {
                match self.h3_conn.submit_wt_request(sid, &headers) {
                    Ok(()) => {
                        // Save the session ID; the stream ID becomes the session ID.
                        self.session_id = Some(sid);
                        // Actually send the CONNECT request.
                        self.flush().await?;
                        return Ok(sid);
                    }
                    Err(Error::Nghttp3(_, -102)) => {
                        // ERR_INVALID_STATE means SETTINGS are not exchanged yet.
                        // Retry on the same stream.
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
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
                result = self.socket.recv_from(&mut self.recv_buf) => {
                    match result {
                        Ok((len, from)) => {
                            if from == self.remote_addr {
                                let data = self.recv_buf[..len].to_vec();
                                self.handle_recv(&data)?;
                            }
                        }
                        Err(e) => {
                            return Err(Error::Internal(format!("recv error: {}", e)));
                        }
                    }
                }

                _ = tokio::time::sleep(timer_duration) => {
                    let ts = timestamp();
                    self.conn.handle_expiry(ts)?;
                }

                _ = tokio::time::sleep_until(deadline) => {
                    return Err(Error::Internal("settings exchange timeout".to_string()));
                }
            }
        }
    }

    /// Opens a bidirectional stream.
    pub fn open_bidi_stream(&mut self) -> Result<StreamId> {
        let session_id = self
            .session_id
            .ok_or(Error::Internal("session not established".to_string()))?;

        // Open the QUIC stream.
        let stream_id = self.conn.open_bidi_stream()?;

        // Register it as a WebTransport data stream.
        self.h3_conn.open_wt_data_stream(session_id, stream_id)?;

        Ok(stream_id)
    }

    /// Opens a unidirectional stream.
    pub fn open_uni_stream(&mut self) -> Result<StreamId> {
        let session_id = self
            .session_id
            .ok_or(Error::Internal("session not established".to_string()))?;

        // Open the QUIC unidirectional stream.
        let stream_id = self.conn.open_uni_stream()?;

        // Register it as a WebTransport data stream.
        self.h3_conn.open_wt_data_stream(session_id, stream_id)?;

        Ok(stream_id)
    }

    /// Sends data on a WebTransport stream.
    ///
    /// Sends application data on a stream opened by `open_bidi_stream()`. Data
    /// is sent through nghttp3's WebTransport framing.
    ///
    /// Data larger than the QUIC congestion window is sent over multiple
    /// iterations while ACKs arrive. This blocks until all data is handed to
    /// ngtcp2's buffers.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - Stream ID returned by `open_bidi_stream()`.
    /// * `data` - Data to send.
    /// * `fin` - Whether to finish the stream.
    pub async fn send_stream_data(
        &mut self,
        stream_id: StreamId,
        data: &[u8],
        fin: bool,
    ) -> Result<()> {
        self.h3_conn.send_wt_stream_data(stream_id, data, fin)?;

        // Keep flushing until all data is handed to ngtcp2. When the congestion
        // window is full, StreamDataBlocked is returned; receive ACKs to grow
        // the window, unblock the stream, and retry.
        loop {
            let ts = timestamp();
            let (h3_packets, blocked_streams) = self.write_h3_streams_tracked(ts)?;

            for pkt in h3_packets {
                self.socket
                    .send_to(&pkt, self.remote_addr)
                    .await
                    .map_err(|e| Error::Internal(format!("send error: {}", e)))?;
            }

            // Send remaining QUIC packets.
            loop {
                let ts = timestamp();
                let (written, _) = self.conn.write_pkt(&mut self.send_buf, ts)?;
                if written == 0 {
                    break;
                }
                self.socket
                    .send_to(&self.send_buf[..written], self.remote_addr)
                    .await
                    .map_err(|e| Error::Internal(format!("send error: {}", e)))?;
            }

            if blocked_streams.is_empty() {
                // No blocked stream means all data was handed to ngtcp2.
                break;
            }

            // Congestion window is full; receive ACKs to grow it.
            self.recv_ack(Duration::from_millis(50)).await?;

            // Make the blocked stream resumable.
            for sid in &blocked_streams {
                self.h3_conn.unblock_stream(*sid)?;
            }
        }

        Ok(())
    }

    /// Polls the next event.
    pub fn poll(&mut self) -> Option<Http3Event> {
        self.h3_conn.poll_event()
    }

    /// Sends a WebTransport DATAGRAM.
    ///
    /// Sends a DATAGRAM through the WebTransport session. DATAGRAM delivery is
    /// unreliable and unordered.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to send.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Data was queued for sending.
    /// * `Ok(false)` - Data was not accepted, for example due to congestion control.
    pub async fn send_datagram(&mut self, data: &[u8]) -> Result<bool> {
        let session_id = self
            .session_id
            .ok_or(Error::Internal("session not established".to_string()))?;

        // Check remote DATAGRAM support.
        if !self.conn.can_send_datagram() {
            return Err(Error::Internal(
                "remote peer does not support DATAGRAM".to_string(),
            ));
        }

        // HTTP/3 DATAGRAM format: Quarter Stream ID + Payload.
        // Quarter Stream ID = session_id / 4
        let quarter_stream_id = session_id as u64 / 4;
        let mut datagram = Vec::with_capacity(8 + data.len());
        varint::encode_to_vec(quarter_stream_id, &mut datagram);
        datagram.extend_from_slice(data);

        // Send as a QUIC DATAGRAM.
        let ts = timestamp();
        let (written, accepted) = self
            .conn
            .write_datagram(&mut self.send_buf, &datagram, ts)?;

        if written > 0 {
            self.socket
                .send_to(&self.send_buf[..written], self.remote_addr)
                .await
                .map_err(|e| Error::Internal(format!("send error: {}", e)))?;
        }

        Ok(accepted)
    }

    /// Receives a WebTransport DATAGRAM.
    ///
    /// Pops a DATAGRAM from the receive queue. DATAGRAMs for other sessions are
    /// ignored.
    ///
    /// # Returns
    ///
    /// * `Some(data)` - Received DATAGRAM payload.
    /// * `None` - No data available.
    pub fn recv_datagram(&mut self) -> Option<Vec<u8>> {
        let session_id = self.session_id?;
        let expected_quarter_stream_id = session_id as u64 / 4;

        while let Some(datagram) = self.conn.poll_datagram() {
            // Decode Quarter Stream ID.
            if let Some((quarter_stream_id, consumed)) = varint::decode(&datagram.data)
                && quarter_stream_id == expected_quarter_stream_id
            {
                return Some(datagram.data[consumed..].to_vec());
            }
        }

        None
    }

    /// Runs one network I/O step.
    ///
    /// Flushes outgoing data, receives one packet, and processes it. Events can
    /// be read with `poll()` afterwards.
    pub async fn recv(&mut self, timeout: Duration) -> Result<()> {
        // Flush outgoing data.
        self.flush().await?;

        // Calculate timeout.
        let expiry = self.conn.get_expiry();
        let now = timestamp();
        let timer_duration = if expiry > now {
            Duration::from_nanos(expiry - now).min(timeout)
        } else {
            Duration::from_millis(1)
        };

        tokio::select! {
            result = self.socket.recv_from(&mut self.recv_buf) => {
                match result {
                    Ok((len, from)) => {
                        if from == self.remote_addr {
                            let data = self.recv_buf[..len].to_vec();
                            self.handle_recv(&data)?;
                        }
                    }
                    Err(e) => {
                        return Err(Error::Internal(format!("recv error: {}", e)));
                    }
                }
            }
            _ = tokio::time::sleep(timer_duration) => {
                let ts = timestamp();
                self.conn.handle_expiry(ts)?;
            }
        }

        Ok(())
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
                result = self.socket.recv_from(&mut self.recv_buf) => {
                    match result {
                        Ok((len, from)) => {
                            if from == self.remote_addr {
                                let data = self.recv_buf[..len].to_vec();
                                self.handle_recv(&data)?;
                            }
                        }
                        Err(e) => {
                            return Err(Error::Internal(format!("recv error: {}", e)));
                        }
                    }
                }

                _ = tokio::time::sleep(timer_duration) => {
                    let ts = timestamp();
                    self.conn.handle_expiry(ts)?;
                }
            }
        }
    }

    /// Binds control streams.
    fn bind_control_streams(&mut self) -> Result<()> {
        let ctrl_stream_id = self.conn.open_uni_stream()?;
        self.h3_conn.bind_control_stream(ctrl_stream_id)?;

        let qpack_enc_stream_id = self.conn.open_uni_stream()?;
        let qpack_dec_stream_id = self.conn.open_uni_stream()?;
        self.h3_conn
            .bind_qpack_streams(qpack_enc_stream_id, qpack_dec_stream_id)?;

        self.control_streams_bound = true;
        Ok(())
    }

    /// Handles received data.
    fn handle_recv(&mut self, data: &[u8]) -> Result<()> {
        let ts = timestamp();
        let pkt_info = PacketInfo::default();
        self.conn
            .read_pkt(&self.local_addr, &self.remote_addr, &pkt_info, data, ts)?;

        // Pass received stream data to HTTP/3.
        self.process_stream_data(ts)?;

        Ok(())
    }

    /// Passes stream data to HTTP/3.
    fn process_stream_data(&mut self, ts: u64) -> Result<()> {
        while let Some(stream_data) = self.conn.poll_stream_data() {
            // Pass stream data to HTTP/3.
            let consumed = self.h3_conn.read_stream(
                stream_data.stream_id,
                &stream_data.data,
                stream_data.fin,
                ts,
            )?;

            // Extend the offset by the consumed byte count.
            if consumed > 0 {
                self.conn
                    .extend_max_stream_offset(stream_data.stream_id, consumed as u64)?;
                self.conn.extend_max_offset(consumed as u64);
            }
        }
        Ok(())
    }

    /// Flushes outgoing data.
    async fn flush(&mut self) -> Result<()> {
        let ts = timestamp();

        // Send HTTP/3 data after the handshake completes and control streams are bound.
        if self.conn.is_handshake_completed() && self.control_streams_bound {
            // Collect HTTP/3 stream data synchronously.
            let h3_packets = self.write_h3_streams(ts)?;

            // Send packets.
            for pkt in h3_packets {
                self.socket
                    .send_to(&pkt, self.remote_addr)
                    .await
                    .map_err(|e| Error::Internal(format!("send error: {}", e)))?;
            }
        }

        // Send remaining QUIC packets.
        loop {
            let (written, _pkt_info) = self.conn.write_pkt(&mut self.send_buf, ts)?;

            if written == 0 {
                break;
            }

            self.socket
                .send_to(&self.send_buf[..written], self.remote_addr)
                .await
                .map_err(|e| Error::Internal(format!("send error: {}", e)))?;
        }

        Ok(())
    }

    /// Receives ACKs without calling flush.
    ///
    /// Used inside the congestion-control loop in `send_stream_data`. Normal
    /// `recv()` flushes first; this method intentionally skips that.
    async fn recv_ack(&mut self, timeout: Duration) -> Result<()> {
        let expiry = self.conn.get_expiry();
        let now = timestamp();
        let timer_duration = if expiry > now {
            Duration::from_nanos(expiry - now).min(timeout)
        } else {
            Duration::from_millis(1)
        };

        tokio::select! {
            result = self.socket.recv_from(&mut self.recv_buf) => {
                match result {
                    Ok((len, from)) => {
                        if from == self.remote_addr {
                            let data = self.recv_buf[..len].to_vec();
                            self.handle_recv(&data)?;
                        }
                    }
                    Err(e) => {
                        return Err(Error::Internal(format!("recv error: {}", e)));
                    }
                }
            }
            _ = tokio::time::sleep(timer_duration) => {
                let ts = timestamp();
                self.conn.handle_expiry(ts)?;
            }
        }

        Ok(())
    }

    /// Writes HTTP/3 stream data and returns a congestion-blocked stream ID.
    ///
    /// Used inside the congestion-control loop in `send_stream_data`.
    fn write_h3_streams_tracked(&mut self, ts: u64) -> Result<(Vec<Vec<u8>>, Vec<StreamId>)> {
        use ngtcp2::nghttp3_vec;

        let mut packets = Vec::new();
        let mut blocked = Vec::new();

        let mut vecs = [nghttp3_vec {
            base: std::ptr::null_mut(),
            len: 0,
        }; 16];

        while let Ok((sid, fin, count)) = self.h3_conn.write_stream(&mut vecs) {
            if count == 0 {
                break;
            }

            let mut h3_data = Vec::new();
            for vec in vecs.iter().take(count) {
                if vec.len == 0 || vec.base.is_null() {
                    continue;
                }
                let data = unsafe { std::slice::from_raw_parts(vec.base as *const u8, vec.len) };
                h3_data.extend_from_slice(data);
            }

            if h3_data.is_empty() {
                continue;
            }

            let result = self
                .conn
                .write_stream(&mut self.send_buf, sid, &h3_data, fin, ts);

            match result {
                Ok((pkt_written, data_written)) => {
                    if pkt_written > 0 {
                        packets.push(self.send_buf[..pkt_written].to_vec());
                    }
                    if let Some(dw) = data_written
                        && dw > 0
                    {
                        self.h3_conn.add_write_offset(sid, dw)?;
                    } else if pkt_written == 0 {
                        // The ngtcp2 congestion window was full, so data could not be written.
                        self.h3_conn.block_stream(sid);
                        blocked.push(sid);
                        break;
                    }
                }
                Err(Error::StreamDataBlocked(_)) => {
                    self.h3_conn.block_stream(sid);
                    blocked.push(sid);
                    continue;
                }
                Err(Error::StreamShutWr(_)) => {
                    self.h3_conn.shutdown_stream_write(sid);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Ok((packets, blocked))
    }

    /// Writes HTTP/3 stream data synchronously and collects packets.
    ///
    /// Handles selected errors following the ngtcp2 examples.
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

            // Copy from nghttp3_vec.
            let mut h3_data = Vec::new();
            for vec in vecs.iter().take(count) {
                if vec.len == 0 || vec.base.is_null() {
                    continue;
                }
                let data = unsafe { std::slice::from_raw_parts(vec.base as *const u8, vec.len) };
                h3_data.extend_from_slice(data);
            }

            if h3_data.is_empty() {
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
                    self.h3_conn.block_stream(stream_id);
                    continue;
                }
                Err(Error::StreamShutWr(_)) => {
                    self.h3_conn.shutdown_stream_write(stream_id);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(packets)
    }
}

/// WebTransport server session.
pub struct ServerWebTransportSession {
    socket: Socket,
    local_addr: SocketAddr,
    // TLS context.
    tls_ctx: TlsContext,
    // Transport parameters.
    transport_params: ngtcp2_transport_params,
    // HTTP/3 settings.
    h3_settings: nghttp3_settings,
    // Connection map.
    connections: std::collections::HashMap<SocketAddr, ServerWtConnection>,
    // Receive buffer.
    recv_buf: Vec<u8>,
    // Send buffer.
    send_buf: Vec<u8>,
}

struct ServerWtConnection {
    conn: Connection,
    h3_conn: Http3Connection,
    // WebTransport session ID.
    session_id: Option<SessionId>,
    control_streams_bound: bool,
    // Set of streams already opened through open_wt_data_stream.
    opened_wt_streams: std::collections::HashSet<StreamId>,
}

// SAFETY: All fields in ServerWebTransportSession are Send/Sync.
unsafe impl Send for ServerWebTransportSession {}
unsafe impl Sync for ServerWebTransportSession {}

impl ServerWebTransportSession {
    /// Creates a WebTransport server.
    pub async fn bind(addr: SocketAddr, cert_path: &Path, key_path: &Path) -> Result<Self> {
        let socket = Socket::bind(addr)
            .await
            .map_err(|e| Error::Internal(format!("failed to bind socket: {}", e)))?;

        let local_addr = socket.local_addr();

        // Create the TLS context.
        let tls_ctx = TlsContext::new_server(cert_path, key_path, &[b"h3"])?;

        // Transport parameters for WebTransport with DATAGRAM enabled.
        let transport_params = ngtcp2_transport_params::default_params().with_datagram(65535);

        // HTTP/3 settings for WebTransport.
        let h3_settings = nghttp3_settings::default_settings().with_webtransport();

        Ok(Self {
            socket,
            local_addr,
            tls_ctx,
            transport_params,
            h3_settings,
            connections: std::collections::HashMap::new(),
            recv_buf: vec![0u8; 65535],
            send_buf: vec![0u8; 1350],
        })
    }

    /// Returns the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Runs the server.
    ///
    /// # Arguments
    ///
    /// * `handler` - WebTransport event handler.
    ///   - Arguments: `(client_address, session_id, HTTP/3 event)`.
    ///   - Return `true` to accept the session.
    pub async fn run<F>(&mut self, mut handler: F) -> Result<()>
    where
        F: FnMut(SocketAddr, SessionId, Http3Event) -> bool,
    {
        loop {
            let timer_duration = self.compute_timer_duration();

            tokio::select! {
                result = self.socket.recv_from(&mut self.recv_buf) => {
                    match result {
                        Ok((len, from)) => {
                            let data = self.recv_buf[..len].to_vec();
                            self.handle_recv(&data, from, &mut handler).await?;
                        }
                        Err(e) => {
                            eprintln!("[webtransport server] recv error: {}", e);
                            continue;
                        }
                    }
                }

                _ = tokio::time::sleep(timer_duration) => {
                    self.handle_timeouts().await?;
                }
            }

            self.flush_all().await?;
            self.remove_closed_connections();
        }
    }

    fn compute_timer_duration(&self) -> Duration {
        let now = timestamp();
        let mut min_duration = Duration::from_secs(1);

        for conn in self.connections.values() {
            let expiry = conn.conn.get_expiry();
            if expiry > now {
                let duration = Duration::from_nanos(expiry - now);
                if duration < min_duration {
                    min_duration = duration;
                }
            } else {
                return Duration::from_millis(1);
            }
        }

        min_duration
    }

    async fn handle_recv<F>(&mut self, data: &[u8], from: SocketAddr, handler: &mut F) -> Result<()>
    where
        F: FnMut(SocketAddr, SessionId, Http3Event) -> bool,
    {
        let ts = timestamp();
        let pkt_info = PacketInfo::default();

        if let Some(conn) = self.connections.get_mut(&from) {
            conn.conn
                .read_pkt(&self.local_addr, &from, &pkt_info, data, ts)?;

            // Pass received stream data to HTTP/3.
            while let Some(stream_data) = conn.conn.poll_stream_data() {
                let consumed = conn.h3_conn.read_stream(
                    stream_data.stream_id,
                    &stream_data.data,
                    stream_data.fin,
                    ts,
                )?;
                if consumed > 0 {
                    conn.conn
                        .extend_max_stream_offset(stream_data.stream_id, consumed as u64)?;
                    conn.conn.extend_max_offset(consumed as u64);
                }
            }

            let handshake_completed = conn.conn.is_handshake_completed();
            if handshake_completed && !conn.control_streams_bound {
                bind_wt_control_streams(conn)?;
            }

            // Process HTTP/3 events.
            while let Some(event) = conn.h3_conn.poll_event() {
                // Handle WebTransport CONNECT requests.
                if let Http3Event::HeadersEnd { stream_id, .. } = &event {
                    let session_id = *stream_id;
                    if handler(from, session_id, event) {
                        // Accept the session.
                        let response_headers = vec![Header::status(200)];
                        conn.h3_conn
                            .submit_wt_response(session_id, &response_headers)?;
                        conn.h3_conn.server_confirm_wt_session(session_id, ts)?;
                        conn.session_id = Some(session_id);
                    }
                } else if let Some(session_id) = conn.session_id {
                    handler(from, session_id, event);
                }
            }

            return Ok(());
        }

        // Create a new connection.
        if data.len() < 6 {
            return Ok(());
        }

        let first_byte = data[0];
        if first_byte & 0x80 == 0 {
            // Short headers should be routed to existing connections.
            return Ok(());
        }

        // Read the QUIC version from bytes 1-4 in big-endian order. Currently
        // unused because this wrapper does not do version negotiation.
        let _version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

        // DCID Length (offset 5)
        let dcid_len = data[5] as usize;
        if data.len() < 6 + dcid_len {
            return Ok(());
        }
        let original_dcid_bytes = &data[6..6 + dcid_len];
        let original_dcid = match ConnectionId::new(original_dcid_bytes) {
            Some(cid) => cid,
            None => {
                return Ok(());
            }
        };

        // SCID Length (offset 6 + DCID_len)
        let scid_offset = 6 + dcid_len;
        if data.len() < scid_offset + 1 {
            return Ok(());
        }
        let client_scid_len = data[scid_offset] as usize;
        if data.len() < scid_offset + 1 + client_scid_len {
            return Ok(());
        }
        let client_scid_bytes = &data[scid_offset + 1..scid_offset + 1 + client_scid_len];
        let client_scid = match ConnectionId::new(client_scid_bytes) {
            Some(cid) => cid,
            None => {
                return Ok(());
            }
        };

        let server_scid = ConnectionId::random(16)
            .ok_or(Error::Internal("failed to generate scid".to_string()))?;

        let tls_session = self.tls_ctx.create_session()?;

        // Build server transport parameters. original_dcid is the DCID from
        // the client's first Initial packet.
        let params = self.transport_params.with_original_dcid(&original_dcid);

        // For server_new:
        // - dcid is the client's SCID, used as the DCID in server-to-client packets.
        // - scid is the server's SCID.
        let mut conn = Connection::server_new(
            &client_scid,
            &server_scid,
            self.local_addr,
            from,
            tls_session,
            &params,
            ts,
        )?;

        conn.read_pkt(&self.local_addr, &from, &pkt_info, data, ts)?;

        let h3_conn = Http3Connection::server_new(&self.h3_settings)?;

        let server_conn = ServerWtConnection {
            conn,
            h3_conn,
            session_id: None,
            control_streams_bound: false,
            opened_wt_streams: std::collections::HashSet::new(),
        };

        self.connections.insert(from, server_conn);

        Ok(())
    }

    async fn handle_timeouts(&mut self) -> Result<()> {
        let ts = timestamp();

        for conn in self.connections.values_mut() {
            let expiry = conn.conn.get_expiry();
            if expiry <= ts {
                conn.conn.handle_expiry(ts)?;
            }
        }

        Ok(())
    }

    async fn flush_all(&mut self) -> Result<()> {
        let ts = timestamp();

        let addrs: Vec<SocketAddr> = self.connections.keys().copied().collect();

        for addr in addrs {
            // Write HTTP/3 stream data and collect packets synchronously.
            let h3_packets = if let Some(conn) = self.connections.get_mut(&addr) {
                write_h3_streams_for_wt_connection(conn, &mut self.send_buf, ts)?
            } else {
                Vec::new()
            };

            // Send collected HTTP/3 packets.
            for pkt in h3_packets {
                self.socket
                    .send_to(&pkt, addr)
                    .await
                    .map_err(|e| Error::Internal(format!("send error: {}", e)))?;
            }

            // Send remaining QUIC packets.
            if let Some(conn) = self.connections.get_mut(&addr) {
                loop {
                    let (written, _pkt_info) = conn.conn.write_pkt(&mut self.send_buf, ts)?;

                    if written == 0 {
                        break;
                    }

                    self.socket
                        .send_to(&self.send_buf[..written], addr)
                        .await
                        .map_err(|e| Error::Internal(format!("send error: {}", e)))?;
                }
            }
        }

        Ok(())
    }

    fn remove_closed_connections(&mut self) {
        self.connections.retain(|addr, conn| {
            let should_remove =
                conn.conn.is_in_closing_period() || conn.conn.is_in_draining_period();
            if should_remove {
                eprintln!("[webtransport server] connection closed: {}", addr);
            }
            !should_remove
        });
    }

    /// Opens a bidirectional stream on a specific connection.
    pub fn open_bidi_stream_for(&mut self, addr: &SocketAddr) -> Result<StreamId> {
        let conn = self
            .connections
            .get_mut(addr)
            .ok_or(Error::Internal(format!("connection not found: {}", addr)))?;
        let session_id = conn
            .session_id
            .ok_or(Error::Internal("session not established".to_string()))?;
        let stream_id = conn.conn.open_bidi_stream()?;
        conn.h3_conn.open_wt_data_stream(session_id, stream_id)?;
        conn.opened_wt_streams.insert(stream_id);
        Ok(stream_id)
    }

    /// Sends data on a stream for a specific connection.
    pub fn send_stream_data_for(
        &mut self,
        addr: &SocketAddr,
        stream_id: StreamId,
        data: &[u8],
        fin: bool,
    ) -> Result<()> {
        let conn = self
            .connections
            .get_mut(addr)
            .ok_or(Error::Internal(format!("connection not found: {}", addr)))?;
        let session_id = conn
            .session_id
            .ok_or(Error::Internal("session not established".to_string()))?;
        // A client-initiated stream must be registered with open_wt_data_stream
        // before the first write.
        if conn.opened_wt_streams.insert(stream_id) {
            conn.h3_conn.open_wt_data_stream(session_id, stream_id)?;
        }
        conn.h3_conn.send_wt_stream_data(stream_id, data, fin)?;
        Ok(())
    }

    /// Receives and processes one packet.
    ///
    /// Performs one receive step and flushes output, instead of looping like
    /// `run()`. Useful alongside stream creation and data sending.
    pub async fn recv_once<F>(&mut self, timeout_duration: Duration, handler: &mut F) -> Result<()>
    where
        F: FnMut(SocketAddr, SessionId, Http3Event) -> bool,
    {
        let timer_duration = self.compute_timer_duration().min(timeout_duration);

        tokio::select! {
            result = self.socket.recv_from(&mut self.recv_buf) => {
                match result {
                    Ok((len, from)) => {
                        let data = self.recv_buf[..len].to_vec();
                        self.handle_recv(&data, from, handler).await?;
                    }
                    Err(e) => {
                        return Err(Error::Internal(format!("recv error: {}", e)));
                    }
                }
            }
            _ = tokio::time::sleep(timer_duration) => {
                self.handle_timeouts().await?;
            }
        }

        self.flush_all().await?;
        self.remove_closed_connections();
        Ok(())
    }

    /// Returns the address for a connection with an established session.
    pub fn get_established_addrs(&self) -> Vec<SocketAddr> {
        self.connections
            .iter()
            .filter(|(_, conn)| conn.session_id.is_some())
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// Flushes outgoing data.
    pub async fn flush(&mut self) -> Result<()> {
        self.flush_all().await
    }

    /// Sends a DATAGRAM to a specific client.
    ///
    /// Sends a DATAGRAM to a specific client through a WebTransport session.
    /// DATAGRAM delivery is unreliable and unordered.
    ///
    /// # Arguments
    ///
    /// * `addr` - Destination client address.
    /// * `data` - Data to send.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Data was queued for sending.
    /// * `Ok(false)` - Data was not accepted, for example due to congestion control.
    pub async fn send_datagram_for(&mut self, addr: &SocketAddr, data: &[u8]) -> Result<bool> {
        let conn = self
            .connections
            .get_mut(addr)
            .ok_or(Error::Internal(format!("connection not found: {}", addr)))?;

        let session_id = conn
            .session_id
            .ok_or(Error::Internal("session not established".to_string()))?;

        // Check remote DATAGRAM support.
        if !conn.conn.can_send_datagram() {
            return Err(Error::Internal(
                "remote peer does not support DATAGRAM".to_string(),
            ));
        }

        // HTTP/3 DATAGRAM format: Quarter Stream ID + Payload.
        // Quarter Stream ID = session_id / 4
        let quarter_stream_id = session_id as u64 / 4;
        let mut datagram = Vec::with_capacity(8 + data.len());
        varint::encode_to_vec(quarter_stream_id, &mut datagram);
        datagram.extend_from_slice(data);

        // Send as a QUIC DATAGRAM.
        let ts = timestamp();
        let (written, accepted) = conn
            .conn
            .write_datagram(&mut self.send_buf, &datagram, ts)?;

        if written > 0 {
            self.socket
                .send_to(&self.send_buf[..written], *addr)
                .await
                .map_err(|e| Error::Internal(format!("send error: {}", e)))?;
        }

        Ok(accepted)
    }

    /// Receives a DATAGRAM from a specific client.
    ///
    /// Pops a DATAGRAM from the specified client's receive queue. DATAGRAMs for
    /// other sessions are ignored.
    ///
    /// # Arguments
    ///
    /// * `addr` - Client address.
    ///
    /// # Returns
    ///
    /// * `Some(data)` - Received DATAGRAM payload.
    /// * `None` - No data available.
    pub fn recv_datagram_for(&mut self, addr: &SocketAddr) -> Option<Vec<u8>> {
        let conn = self.connections.get_mut(addr)?;
        let session_id = conn.session_id?;
        let expected_quarter_stream_id = session_id as u64 / 4;

        while let Some(datagram) = conn.conn.poll_datagram() {
            // Decode Quarter Stream ID.
            if let Some((quarter_stream_id, consumed)) = varint::decode(&datagram.data)
                && quarter_stream_id == expected_quarter_stream_id
            {
                return Some(datagram.data[consumed..].to_vec());
            }
        }

        None
    }

    /// Opens a unidirectional stream on a specific connection.
    pub fn open_uni_stream_for(&mut self, addr: &SocketAddr) -> Result<StreamId> {
        let conn = self
            .connections
            .get_mut(addr)
            .ok_or(Error::Internal(format!("connection not found: {}", addr)))?;
        let session_id = conn
            .session_id
            .ok_or(Error::Internal("session not established".to_string()))?;
        let stream_id = conn.conn.open_uni_stream()?;
        conn.h3_conn.open_wt_data_stream(session_id, stream_id)?;
        conn.opened_wt_streams.insert(stream_id);
        Ok(stream_id)
    }
}

fn bind_wt_control_streams(conn: &mut ServerWtConnection) -> Result<()> {
    let ctrl_stream_id = conn.conn.open_uni_stream()?;
    conn.h3_conn.bind_control_stream(ctrl_stream_id)?;

    let qpack_enc_stream_id = conn.conn.open_uni_stream()?;
    let qpack_dec_stream_id = conn.conn.open_uni_stream()?;
    conn.h3_conn
        .bind_qpack_streams(qpack_enc_stream_id, qpack_dec_stream_id)?;

    conn.control_streams_bound = true;
    Ok(())
}

/// Writes HTTP/3 stream data and collects packets synchronously.
///
/// Handles selected errors following the ngtcp2 examples.
fn write_h3_streams_for_wt_connection(
    conn: &mut ServerWtConnection,
    send_buf: &mut [u8],
    ts: u64,
) -> Result<Vec<Vec<u8>>> {
    use ngtcp2::nghttp3_vec;

    let mut packets = Vec::new();

    // Process HTTP/3 streams only after the handshake completes.
    if !conn.conn.is_handshake_completed() || !conn.control_streams_bound {
        return Ok(packets);
    }

    // Get data to write from HTTP/3.
    let mut vecs = [nghttp3_vec {
        base: std::ptr::null_mut(),
        len: 0,
    }; 16];

    while let Ok((stream_id, fin, count)) = conn.h3_conn.write_stream(&mut vecs) {
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

        if h3_data.is_empty() {
            continue;
        }

        // Write to the QUIC stream and handle selected errors following the
        // ngtcp2 examples.
        let result = conn
            .conn
            .write_stream(send_buf, stream_id, &h3_data, fin, ts);

        match result {
            Ok((pkt_written, data_written)) => {
                // Copy and collect the packet.
                if pkt_written > 0 {
                    packets.push(send_buf[..pkt_written].to_vec());
                }

                // Tell nghttp3 how many bytes were written.
                if let Some(dw) = data_written
                    && dw > 0
                {
                    conn.h3_conn.add_write_offset(stream_id, dw)?;
                }
            }
            Err(Error::StreamDataBlocked(_)) => {
                conn.h3_conn.block_stream(stream_id);
                continue;
            }
            Err(Error::StreamShutWr(_)) => {
                conn.h3_conn.shutdown_stream_write(stream_id);
                continue;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    Ok(packets)
}
