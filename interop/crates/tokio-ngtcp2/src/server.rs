//! HTTP/3 server implementation.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use ngtcp2::{
    Connection, ConnectionId, Error, Header, Http3Connection, Http3Event, Http3SettingsExt,
    PacketInfo, Result, StreamId, TlsContext, TransportParamsExt, nghttp3_settings,
    ngtcp2_transport_params,
};

use crate::{Socket, timestamp};

/// HTTP/3 server.
pub struct Server {
    socket: Socket,
    local_addr: SocketAddr,
    // TLS context.
    tls_ctx: TlsContext,
    // Transport parameters kept for future extension.
    #[allow(dead_code)]
    transport_params: ngtcp2_transport_params,
    // HTTP/3 settings.
    h3_settings: nghttp3_settings,
    // Connection map keyed by client address.
    connections: HashMap<SocketAddr, ServerConnection>,
    // Receive buffer.
    recv_buf: Vec<u8>,
    // Send buffer.
    send_buf: Vec<u8>,
}

/// Server-side connection state.
struct ServerConnection {
    // QUIC connection.
    conn: Connection,
    // HTTP/3 connection.
    h3_conn: Http3Connection,
    // Whether control streams are already bound.
    control_streams_bound: bool,
    // Streams blocked by QUIC flow control or congestion. They are made
    // writable again after inbound packets advance ngtcp2 state. This mirrors
    // nghttp3's block/unblock API and is required for large responses that
    // cannot fit into one QUIC send attempt.
    // https://nghttp2.org/nghttp3/nghttp3_conn_block_stream.html
    blocked_streams: Vec<StreamId>,
}

// SAFETY: All fields are Send/Sync. Connection, Http3Connection, and
// TlsContext provide unsafe Send/Sync impls.
unsafe impl Send for Server {}
unsafe impl Sync for Server {}

impl Server {
    /// Creates a new server.
    ///
    /// # Arguments
    ///
    /// * `addr` - Listen address.
    /// * `cert_path` - Certificate file path.
    /// * `key_path` - Private key file path.
    /// * `transport_params` - QUIC transport parameters; defaults when `None`.
    /// * `h3_settings` - HTTP/3 settings; defaults when `None`.
    pub async fn bind(
        addr: SocketAddr,
        cert_path: &Path,
        key_path: &Path,
        transport_params: Option<ngtcp2_transport_params>,
        h3_settings: Option<nghttp3_settings>,
    ) -> Result<Self> {
        let socket = Socket::bind(addr)
            .await
            .map_err(|e| Error::Internal(format!("failed to bind socket: {}", e)))?;

        let local_addr = socket.local_addr();

        // Create the TLS context.
        let tls_ctx = TlsContext::new_server(cert_path, key_path, &[b"h3"])?;

        // Transport parameters.
        let transport_params =
            transport_params.unwrap_or_else(ngtcp2_transport_params::default_params);

        // HTTP/3 settings.
        let h3_settings = h3_settings.unwrap_or_else(nghttp3_settings::default_settings);

        Ok(Self {
            socket,
            local_addr,
            tls_ctx,
            transport_params,
            h3_settings,
            connections: HashMap::new(),
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
    /// * `handler` - Request handler.
    ///   - Arguments: `(client_address, HTTP/3 event)`.
    ///   - Return value: response headers and body, or `None` for no response.
    pub async fn run<F>(&mut self, mut handler: F) -> Result<()>
    where
        F: FnMut(SocketAddr, Http3Event) -> Option<(Vec<Header>, Vec<u8>)>,
    {
        loop {
            // Calculate the next timeout.
            let timer_duration = self.compute_timer_duration();

            tokio::select! {
                // Process incoming data.
                result = self.socket.recv_from(&mut self.recv_buf) => {
                    match result {
                        Ok((len, from)) => {
                            let data = self.recv_buf[..len].to_vec();
                            self.handle_recv(&data, from, &mut handler).await?;
                        }
                        Err(e) => {
                            eprintln!("[tokio-ngtcp2 server] recv error: {}", e);
                            continue;
                        }
                    }
                }

                // Timeout.
                _ = tokio::time::sleep(timer_duration) => {
                    self.handle_timeouts().await?;
                }
            }

            // Flush outgoing data.
            self.flush_all().await?;

            // Remove closed connections.
            self.remove_closed_connections();
        }
    }

    /// Calculates the timeout duration.
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

    /// Handles received data.
    async fn handle_recv<F>(&mut self, data: &[u8], from: SocketAddr, handler: &mut F) -> Result<()>
    where
        F: FnMut(SocketAddr, Http3Event) -> Option<(Vec<Header>, Vec<u8>)>,
    {
        let ts = timestamp();
        let pkt_info = PacketInfo::default();

        // Look up an existing connection.
        if let Some(conn) = self.connections.get_mut(&from) {
            // Process the QUIC packet.
            conn.conn
                .read_pkt(&self.local_addr, &from, &pkt_info, data, ts)?;
            conn.unblock_streams()?;

            // Bind control streams after the handshake completes.
            if conn.conn.is_handshake_completed() && !conn.control_streams_bound {
                bind_server_control_streams(conn)?;
            }

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

            // Process HTTP/3 events.
            while let Some(event) = conn.h3_conn.poll_event() {
                let stream_id = match &event {
                    Http3Event::HeadersEnd { stream_id, .. } => Some(*stream_id),
                    _ => None,
                };

                if let Some((headers, body)) = handler(from, event)
                    && let Some(sid) = stream_id
                {
                    if body.is_empty() {
                        conn.h3_conn.submit_response(sid, &headers)?;
                    } else {
                        conn.h3_conn
                            .submit_response_with_body(sid, &headers, body)?;
                    }
                }
            }

            return Ok(());
        }

        // Create a new connection. Parse the packet header to obtain the DCID.
        if data.len() < 17 {
            return Ok(());
        }

        // Read the DCID from a Long Header packet (RFC 9000 Section 17.2).
        let first_byte = data[0];
        if first_byte & 0x80 == 0 {
            // Short Header packets do not create new connections here.
            return Ok(());
        }

        // Read the QUIC version from bytes 1-4 in big-endian order.
        if data.len() < 5 {
            return Ok(());
        }
        let _version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        // DCID Length (offset 5)
        if data.len() < 6 {
            return Ok(());
        }
        let dcid_len = data[5] as usize;
        if data.len() < 6 + dcid_len {
            return Ok(());
        }
        let original_dcid_bytes = &data[6..6 + dcid_len];
        let original_dcid = match ConnectionId::new(original_dcid_bytes) {
            Some(cid) => cid,
            None => return Ok(()),
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
            None => return Ok(()),
        };

        // Generate the server SCID.
        let server_scid = ConnectionId::random(16)
            .ok_or(Error::Internal("failed to generate scid".to_string()))?;

        // Create the TLS session.
        let tls_session = self.tls_ctx.create_session()?;

        // Build server transport parameters. original_dcid is the DCID from
        // the client's first Initial packet.
        let params = ngtcp2_transport_params::default_params().with_original_dcid(&original_dcid);

        // Create the QUIC connection. For server_new:
        // - dcid is the client's SCID, used as the DCID in server-to-client packets.
        // - scid is the server's SCID.
        let mut conn = match Connection::server_new(
            &client_scid,
            &server_scid,
            self.local_addr,
            from,
            tls_session,
            &params,
            ts,
        ) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        // Process the received packet.
        conn.read_pkt(&self.local_addr, &from, &pkt_info, data, ts)?;

        // Create the HTTP/3 connection.
        let h3_conn = Http3Connection::server_new(&self.h3_settings)?;

        let server_conn = ServerConnection {
            conn,
            h3_conn,
            control_streams_bound: false,
            blocked_streams: Vec::new(),
        };

        self.connections.insert(from, server_conn);

        Ok(())
    }

    /// Handles timeouts for all connections.
    async fn handle_timeouts(&mut self) -> Result<()> {
        let ts = timestamp();

        for conn in self.connections.values_mut() {
            let expiry = conn.conn.get_expiry();
            if expiry <= ts {
                conn.conn.handle_expiry(ts)?;
                conn.unblock_streams()?;
            }
        }

        Ok(())
    }

    /// Flushes outgoing data for all connections.
    async fn flush_all(&mut self) -> Result<()> {
        let ts = timestamp();

        let addrs: Vec<SocketAddr> = self.connections.keys().copied().collect();
        for addr in addrs {
            // Temporarily remove the connection while sending.
            let mut conn = match self.connections.remove(&addr) {
                Some(c) => c,
                None => continue,
            };

            // Write HTTP/3 stream data one item at a time and send immediately.
            // This keeps the nghttp3-provided slices alive until ngtcp2 tells
            // us how many bytes it accepted.
            self.write_and_send_h3_streams(&mut conn, addr, ts).await?;

            // Send remaining QUIC packets.
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

            // Put the connection back.
            self.connections.insert(addr, conn);
        }

        Ok(())
    }

    /// Writes HTTP/3 stream data and sends it immediately.
    ///
    /// Writes one HTTP/3 stream-data item at a time.
    async fn write_and_send_h3_streams(
        &mut self,
        conn: &mut ServerConnection,
        addr: SocketAddr,
        ts: u64,
    ) -> Result<()> {
        use ngtcp2::nghttp3_vec;

        if !conn.conn.is_handshake_completed() || !conn.control_streams_bound {
            return Ok(());
        }

        let mut vecs = [nghttp3_vec {
            base: std::ptr::null_mut(),
            len: 0,
        }; 16];

        while let Ok((stream_id, fin, count)) = conn.h3_conn.write_stream(&mut vecs) {
            if count == 0 {
                if fin && stream_id >= 0 {
                    self.write_and_send_fin(conn, addr, stream_id, ts).await?;
                }
                break;
            }

            let mut h3_data = Vec::new();
            for vec in vecs.iter().take(count) {
                if vec.len == 0 || vec.base.is_null() {
                    continue;
                }
                let data = unsafe { std::slice::from_raw_parts(vec.base as *const u8, vec.len) };
                h3_data.push(data);
            }

            if h3_data.is_empty() && !fin {
                continue;
            }

            // Keep nghttp3's vectors alive until ngtcp2 reports how many bytes
            // the QUIC layer accepted. Copying them into a short-lived Vec can
            // corrupt large responses when ngtcp2 retains bytes for packet loss
            // recovery.
            //
            // ngtcp2 also requires that only the accepted byte count is reported
            // back through nghttp3_conn_add_write_offset.
            // https://nghttp2.org/ngtcp2/ngtcp2_conn_writev_stream.html
            // https://nghttp2.org/nghttp3/nghttp3_conn_add_write_offset.html
            let result =
                conn.conn
                    .write_stream_vectored(&mut self.send_buf, stream_id, &h3_data, fin, ts);

            match result {
                Ok((pkt_written, data_written)) => {
                    if pkt_written > 0 {
                        self.socket
                            .send_to(&self.send_buf[..pkt_written], addr)
                            .await
                            .map_err(|e| Error::Internal(format!("send error: {}", e)))?;
                    }

                    if let Some(accepted) = data_written {
                        conn.h3_conn.add_write_offset(stream_id, accepted)?;
                    }

                    if pkt_written == 0 {
                        if data_written.unwrap_or(0) == 0 {
                            conn.block_stream(stream_id);
                        }
                        break;
                    }
                }
                Err(Error::StreamDataBlocked(_)) => {
                    conn.block_stream(stream_id);
                    continue;
                }
                Err(Error::StreamShutWr(_)) => {
                    conn.h3_conn.shutdown_stream_write(stream_id);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    async fn write_and_send_fin(
        &mut self,
        conn: &mut ServerConnection,
        addr: SocketAddr,
        stream_id: StreamId,
        ts: u64,
    ) -> Result<()> {
        let result = conn
            .conn
            .write_stream(&mut self.send_buf, stream_id, &[], true, ts);

        match result {
            Ok((pkt_written, data_written)) => {
                if pkt_written > 0 {
                    self.socket
                        .send_to(&self.send_buf[..pkt_written], addr)
                        .await
                        .map_err(|e| Error::Internal(format!("send error: {}", e)))?;
                }
                if let Some(dw) = data_written {
                    conn.h3_conn.add_write_offset(stream_id, dw)?;
                }
            }
            Err(Error::StreamDataBlocked(_)) => conn.block_stream(stream_id),
            Err(Error::StreamShutWr(_)) => conn.h3_conn.shutdown_stream_write(stream_id),
            Err(e) => return Err(e),
        }

        Ok(())
    }

    /// Removes closed connections.
    fn remove_closed_connections(&mut self) {
        self.connections.retain(|_, conn| {
            !conn.conn.is_in_closing_period() && !conn.conn.is_in_draining_period()
        });
    }

    /// Sends a response.
    pub fn send_response(
        &mut self,
        client_addr: SocketAddr,
        stream_id: StreamId,
        headers: &[Header],
    ) -> Result<()> {
        let conn = self
            .connections
            .get_mut(&client_addr)
            .ok_or(Error::Internal("connection not found".to_string()))?;

        conn.h3_conn.submit_response(stream_id, headers)?;

        Ok(())
    }
}

impl ServerConnection {
    fn block_stream(&mut self, stream_id: StreamId) {
        self.h3_conn.block_stream(stream_id);
        if !self.blocked_streams.contains(&stream_id) {
            self.blocked_streams.push(stream_id);
        }
    }

    fn unblock_streams(&mut self) -> Result<()> {
        for stream_id in std::mem::take(&mut self.blocked_streams) {
            self.h3_conn.unblock_stream(stream_id)?;
        }

        Ok(())
    }
}

/// Binds server-side control streams.
fn bind_server_control_streams(conn: &mut ServerConnection) -> Result<()> {
    // Control stream.
    let ctrl_stream_id = conn.conn.open_uni_stream()?;
    conn.h3_conn.bind_control_stream(ctrl_stream_id)?;

    // QPACK encoder stream.
    let qpack_enc_stream_id = conn.conn.open_uni_stream()?;

    // QPACK decoder stream.
    let qpack_dec_stream_id = conn.conn.open_uni_stream()?;

    conn.h3_conn
        .bind_qpack_streams(qpack_enc_stream_id, qpack_dec_stream_id)?;

    conn.control_streams_bound = true;
    Ok(())
}
