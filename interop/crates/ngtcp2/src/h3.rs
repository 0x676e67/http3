use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::ptr;

use libc::c_int;
use nghttp3_sys::*;

use crate::error::{Error, Result, check_nghttp3};
use crate::types::{Header, Http3Event, SessionId, StreamId};

/// HTTP/3 connection.
pub struct Http3Connection {
    inner: *mut nghttp3_conn,
    // Event queue. Box the VecDeque metadata so the pointer remains stable even
    // if Http3Connection is moved. VecDeque preserves FIFO order.
    #[allow(clippy::box_collection)]
    events: Box<VecDeque<Http3Event>>,
    // User data passed to nghttp3 callbacks.
    user_data: Box<Http3UserData>,
}

struct Http3UserData {
    events: *mut VecDeque<Http3Event>,
    wt_send_queues: HashMap<i64, WtSendQueue>,
    request_body_queues: HashMap<i64, RequestBodyQueue>,
    response_body_queues: HashMap<i64, ResponseBodyQueue>,
}

/// HTTP/3 request body send queue.
struct RequestBodyQueue {
    data: Vec<u8>,
    offset: usize,
    fin: bool,
}

/// HTTP/3 response body send queue.
struct ResponseBodyQueue {
    data: Vec<u8>,
    offset: usize,
}

// Limit each nghttp3 response-body vector so large interop bodies are emitted
// as a sequence of DATA frames. This keeps the data-reader callback cheap and
// lets the QUIC layer apply flow control between chunks.
// https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.1
const RESPONSE_BODY_CHUNK_SIZE: usize = 16 * 1024;

/// WebTransport stream send queue.
struct WtSendQueue {
    data: Vec<u8>,
    offset: usize,
    fin: bool,
}

/// Body data associated with a stream.
///
/// Stored as `stream_user_data` and returned by data-reader callbacks. Using
/// one common type for request and response bodies lets `on_stream_close` free
/// it in a type-safe way.
struct StreamBodyData {
    data: Vec<u8>,
    offset: usize,
}

// SAFETY: Http3Connection is used internally in a thread-safe manner.
unsafe impl Send for Http3Connection {}
unsafe impl Sync for Http3Connection {}

impl Http3Connection {
    /// Creates a client connection.
    pub fn client_new(settings: &nghttp3_settings) -> Result<Self> {
        let mut events = Box::new(VecDeque::new());
        let events_ptr = &mut *events as *mut VecDeque<Http3Event>;

        let user_data = Box::new(Http3UserData {
            events: events_ptr,
            wt_send_queues: HashMap::new(),
            request_body_queues: HashMap::new(),
            response_body_queues: HashMap::new(),
        });

        let mut conn: *mut nghttp3_conn = ptr::null_mut();

        let callbacks = create_callbacks();

        let rv = unsafe {
            nghttp3_conn_client_new_versioned(
                &mut conn,
                NGHTTP3_CALLBACKS_VERSION as c_int,
                &callbacks,
                NGHTTP3_SETTINGS_VERSION as c_int,
                settings,
                nghttp3_mem_default(),
                &*user_data as *const _ as *mut c_void,
            )
        };

        check_nghttp3(rv)?;

        Ok(Self {
            inner: conn,
            events,
            user_data,
        })
    }

    /// Creates a server connection.
    pub fn server_new(settings: &nghttp3_settings) -> Result<Self> {
        let mut events = Box::new(VecDeque::new());
        let events_ptr = &mut *events as *mut VecDeque<Http3Event>;

        let user_data = Box::new(Http3UserData {
            events: events_ptr,
            wt_send_queues: HashMap::new(),
            request_body_queues: HashMap::new(),
            response_body_queues: HashMap::new(),
        });

        let mut conn: *mut nghttp3_conn = ptr::null_mut();

        let callbacks = create_callbacks();

        let rv = unsafe {
            nghttp3_conn_server_new_versioned(
                &mut conn,
                NGHTTP3_CALLBACKS_VERSION as c_int,
                &callbacks,
                NGHTTP3_SETTINGS_VERSION as c_int,
                settings,
                nghttp3_mem_default(),
                &*user_data as *const _ as *mut c_void,
            )
        };

        check_nghttp3(rv)?;

        Ok(Self {
            inner: conn,
            events,
            user_data,
        })
    }

    /// Binds the control stream.
    pub fn bind_control_stream(&mut self, stream_id: StreamId) -> Result<()> {
        let rv = unsafe { nghttp3_conn_bind_control_stream(self.inner, stream_id) };
        check_nghttp3(rv)
    }

    /// Binds the QPACK streams.
    pub fn bind_qpack_streams(
        &mut self,
        qenc_stream_id: StreamId,
        qdec_stream_id: StreamId,
    ) -> Result<()> {
        let rv =
            unsafe { nghttp3_conn_bind_qpack_streams(self.inner, qenc_stream_id, qdec_stream_id) };
        check_nghttp3(rv)
    }

    /// Reads data from a stream.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - Stream ID.
    /// * `data` - Incoming bytes.
    /// * `fin` - Whether this is the end of the stream.
    /// * `ts` - Current timestamp in nanoseconds.
    pub fn read_stream(
        &mut self,
        stream_id: StreamId,
        data: &[u8],
        fin: bool,
        ts: u64,
    ) -> Result<usize> {
        // Refresh the events pointer in case the boxed queue was moved.
        self.user_data.events = &mut *self.events as *mut VecDeque<Http3Event>;

        let rv = unsafe {
            nghttp3_conn_read_stream2(
                self.inner,
                stream_id,
                data.as_ptr(),
                data.len(),
                if fin { 1 } else { 0 },
                ts,
            )
        };

        if rv < 0 {
            return Err(Error::from_nghttp3(rv as c_int));
        }

        Ok(rv as usize)
    }

    /// Gets data to write to a stream.
    pub fn write_stream(&mut self, buf: &mut [nghttp3_vec]) -> Result<(StreamId, bool, usize)> {
        let mut stream_id: i64 = 0;
        let mut fin: c_int = 0;

        let rv = unsafe {
            nghttp3_conn_writev_stream(
                self.inner,
                &mut stream_id,
                &mut fin,
                buf.as_mut_ptr(),
                buf.len(),
            )
        };

        if rv < 0 {
            return Err(Error::from_nghttp3(rv as c_int));
        }

        Ok((stream_id, fin != 0, rv as usize))
    }

    /// Adds a write offset.
    pub fn add_write_offset(&mut self, stream_id: StreamId, n: usize) -> Result<()> {
        let rv = unsafe { nghttp3_conn_add_write_offset(self.inner, stream_id, n) };
        check_nghttp3(rv)
    }

    /// Adds an ACK offset.
    pub fn add_ack_offset(&mut self, stream_id: StreamId, n: u64) -> Result<()> {
        let rv = unsafe { nghttp3_conn_add_ack_offset(self.inner, stream_id, n) };
        check_nghttp3(rv)
    }

    /// Submits a request.
    pub fn submit_request(&mut self, stream_id: StreamId, headers: &[Header]) -> Result<()> {
        let nvs: Vec<nghttp3_nv> = headers
            .iter()
            .map(|h| nghttp3_nv {
                name: h.name.as_ptr() as *mut _,
                value: h.value.as_ptr() as *mut _,
                namelen: h.name.len(),
                valuelen: h.value.len(),
                flags: NGHTTP3_NV_FLAG_NONE as u8,
            })
            .collect();

        let rv = unsafe {
            nghttp3_conn_submit_request(
                self.inner,
                stream_id,
                nvs.as_ptr(),
                nvs.len(),
                ptr::null(),
                ptr::null_mut(),
            )
        };

        check_nghttp3(rv)
    }

    /// Submits a request with a body.
    ///
    /// The body is queued as one buffer. For large or streaming bodies, call
    /// `submit_request()` first and then use `send_request_body()`.
    pub fn submit_request_with_body(
        &mut self,
        stream_id: StreamId,
        headers: &[Header],
        body: Vec<u8>,
    ) -> Result<()> {
        let nvs: Vec<nghttp3_nv> = headers
            .iter()
            .map(|h| nghttp3_nv {
                name: h.name.as_ptr() as *mut _,
                value: h.value.as_ptr() as *mut _,
                namelen: h.name.len(),
                valuelen: h.value.len(),
                flags: NGHTTP3_NV_FLAG_NONE as u8,
            })
            .collect();

        // Store the body data for the data-reader callback.
        let body_data = Box::new(StreamBodyData {
            data: body,
            offset: 0,
        });
        let body_data_ptr = Box::into_raw(body_data);

        // Configure the data_reader for a request body.
        let dr = nghttp3_data_reader {
            read_data: Some(body_read_data_callback),
        };

        let rv = unsafe {
            nghttp3_conn_submit_request(
                self.inner,
                stream_id,
                nvs.as_ptr(),
                nvs.len(),
                &dr,
                body_data_ptr as *mut c_void,
            )
        };

        if rv < 0 {
            // Free the body data on error.
            unsafe { drop(Box::from_raw(body_data_ptr)) };
            return Err(Error::Nghttp3("submit_request failed".to_string(), rv));
        }

        Ok(())
    }

    /// Starts a request that will stream its body.
    ///
    /// Use together with `send_request_body()`. This submits headers first; the
    /// body is sent later through `send_request_body()`.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - Stream ID.
    /// * `headers` - Request headers.
    pub fn submit_request_streaming(
        &mut self,
        stream_id: StreamId,
        headers: &[Header],
    ) -> Result<()> {
        let nvs: Vec<nghttp3_nv> = headers
            .iter()
            .map(|h| nghttp3_nv {
                name: h.name.as_ptr() as *mut _,
                value: h.value.as_ptr() as *mut _,
                namelen: h.name.len(),
                valuelen: h.value.len(),
                flags: NGHTTP3_NV_FLAG_NONE as u8,
            })
            .collect();

        // Configure the data_reader used by the streaming body queue.
        let dr = nghttp3_data_reader {
            read_data: Some(request_body_queue_read_data_callback),
        };

        let rv = unsafe {
            nghttp3_conn_submit_request(
                self.inner,
                stream_id,
                nvs.as_ptr(),
                nvs.len(),
                &dr,
                ptr::null_mut(),
            )
        };

        check_nghttp3(rv)
    }

    /// Adds request body data to be sent.
    ///
    /// Sends additional body data for a request started with
    /// `submit_request_streaming()`. Data is queued and sent on the next
    /// `write_stream()` call.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - Stream ID.
    /// * `data` - Data to send.
    /// * `fin` - Whether to finish the stream.
    pub fn send_request_body(&mut self, stream_id: StreamId, data: &[u8], fin: bool) -> Result<()> {
        let queue = self
            .user_data
            .request_body_queues
            .entry(stream_id)
            .or_insert(RequestBodyQueue {
                data: Vec::new(),
                offset: 0,
                fin: false,
            });

        queue.data.extend_from_slice(data);
        if fin {
            queue.fin = true;
        }

        // Tell nghttp3 that stream data is available.
        self.resume_stream(stream_id)?;

        Ok(())
    }

    /// Sends a response without a body.
    pub fn submit_response(&mut self, stream_id: StreamId, headers: &[Header]) -> Result<()> {
        let nvs: Vec<nghttp3_nv> = headers
            .iter()
            .map(|h| nghttp3_nv {
                name: h.name.as_ptr() as *mut _,
                value: h.value.as_ptr() as *mut _,
                namelen: h.name.len(),
                valuelen: h.value.len(),
                flags: NGHTTP3_NV_FLAG_NONE as u8,
            })
            .collect();

        // Configure a data_reader for a bodyless response. Returning EOF sends
        // FIN.
        let dr = nghttp3_data_reader {
            read_data: Some(empty_response_read_data_callback),
        };

        let rv = unsafe {
            nghttp3_conn_submit_response(self.inner, stream_id, nvs.as_ptr(), nvs.len(), &dr)
        };

        check_nghttp3(rv)
    }

    /// Sends a response with a body.
    pub fn submit_response_with_body(
        &mut self,
        stream_id: StreamId,
        headers: &[Header],
        body: Vec<u8>,
    ) -> Result<()> {
        let nvs: Vec<nghttp3_nv> = headers
            .iter()
            .map(|h| nghttp3_nv {
                name: h.name.as_ptr() as *mut _,
                value: h.value.as_ptr() as *mut _,
                namelen: h.name.len(),
                valuelen: h.value.len(),
                flags: NGHTTP3_NV_FLAG_NONE as u8,
            })
            .collect();

        // Keep response bytes in connection user data instead of
        // stream_user_data. The queue is cleaned up on stream close, and the
        // callback can return smaller chunks while preserving the backing
        // allocation for nghttp3/ngtcp2 write-offset accounting.
        self.user_data.response_body_queues.insert(
            stream_id,
            ResponseBodyQueue {
                data: body,
                offset: 0,
            },
        );

        // Configure the data_reader for a response body.
        let dr = nghttp3_data_reader {
            read_data: Some(response_body_queue_read_data_callback),
        };

        let rv = unsafe {
            nghttp3_conn_submit_response(self.inner, stream_id, nvs.as_ptr(), nvs.len(), &dr)
        };

        if rv < 0 {
            self.user_data.response_body_queues.remove(&stream_id);
            return Err(Error::Nghttp3("submit_response failed".to_string(), rv));
        }

        Ok(())
    }

    /// Sends trailers.
    pub fn submit_trailers(&mut self, stream_id: StreamId, headers: &[Header]) -> Result<()> {
        let nvs: Vec<nghttp3_nv> = headers
            .iter()
            .map(|h| nghttp3_nv {
                name: h.name.as_ptr() as *mut _,
                value: h.value.as_ptr() as *mut _,
                namelen: h.name.len(),
                valuelen: h.value.len(),
                flags: NGHTTP3_NV_FLAG_NONE as u8,
            })
            .collect();

        let rv =
            unsafe { nghttp3_conn_submit_trailers(self.inner, stream_id, nvs.as_ptr(), nvs.len()) };

        check_nghttp3(rv)
    }

    /// Sends a shutdown notification.
    pub fn submit_shutdown_notice(&mut self) -> Result<()> {
        let rv = unsafe { nghttp3_conn_submit_shutdown_notice(self.inner) };
        check_nghttp3(rv)
    }

    /// Blocks a stream.
    pub fn block_stream(&mut self, stream_id: StreamId) {
        unsafe { nghttp3_conn_block_stream(self.inner, stream_id) };
    }

    /// Unblocks a stream.
    pub fn unblock_stream(&mut self, stream_id: StreamId) -> Result<()> {
        let rv = unsafe { nghttp3_conn_unblock_stream(self.inner, stream_id) };
        check_nghttp3(rv)
    }

    /// Returns whether a stream is writable.
    pub fn is_stream_writable(&self, stream_id: StreamId) -> bool {
        unsafe { nghttp3_conn_is_stream_writable(self.inner, stream_id) != 0 }
    }

    /// Resumes a stream.
    pub fn resume_stream(&mut self, stream_id: StreamId) -> Result<()> {
        let rv = unsafe { nghttp3_conn_resume_stream(self.inner, stream_id) };
        check_nghttp3(rv)
    }

    /// Closes a stream.
    pub fn close_stream(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        let rv = unsafe { nghttp3_conn_close_stream(self.inner, stream_id, error_code) };
        check_nghttp3(rv)
    }

    /// Shuts down stream writes.
    ///
    /// Prevents further writes to the given stream. This is similar to
    /// `block_stream`, but cannot be undone with `unblock_stream`.
    pub fn shutdown_stream_write(&mut self, stream_id: StreamId) {
        unsafe { nghttp3_conn_shutdown_stream_write(self.inner, stream_id) };
    }

    /// Sets the client's maximum bidirectional stream count.
    pub fn set_max_client_streams_bidi(&mut self, max_streams: u64) {
        unsafe { nghttp3_conn_set_max_client_streams_bidi(self.inner, max_streams) };
    }

    /// Polls the next event.
    ///
    /// Events are returned in FIFO order.
    pub fn poll_event(&mut self) -> Option<Http3Event> {
        self.events.pop_front()
    }

    /// Returns the inner pointer.
    pub fn as_ptr(&self) -> *mut nghttp3_conn {
        self.inner
    }

    // ========================================
    // WebTransport helpers.
    // ========================================

    /// Sends a WebTransport request.
    ///
    /// The client sends this to establish a WebTransport session. Headers must
    /// include:
    /// - :method = "CONNECT"
    /// - :scheme = "https"
    /// - :protocol = "webtransport"
    /// - :authority
    /// - :path
    pub fn submit_wt_request(&mut self, stream_id: StreamId, headers: &[Header]) -> Result<()> {
        let nvs: Vec<nghttp3_nv> = headers
            .iter()
            .map(|h| nghttp3_nv {
                name: h.name.as_ptr() as *mut _,
                value: h.value.as_ptr() as *mut _,
                namelen: h.name.len(),
                valuelen: h.value.len(),
                flags: NGHTTP3_NV_FLAG_NONE as u8,
            })
            .collect();

        let rv = unsafe {
            nghttp3_conn_submit_wt_request(
                self.inner,
                stream_id,
                nvs.as_ptr(),
                nvs.len(),
                ptr::null_mut(),
            )
        };

        check_nghttp3(rv)
    }

    /// Sends a WebTransport response.
    ///
    /// The server sends this to accept a WebTransport session. Headers must
    /// include a 2xx status code.
    pub fn submit_wt_response(&mut self, stream_id: StreamId, headers: &[Header]) -> Result<()> {
        let nvs: Vec<nghttp3_nv> = headers
            .iter()
            .map(|h| nghttp3_nv {
                name: h.name.as_ptr() as *mut _,
                value: h.value.as_ptr() as *mut _,
                namelen: h.name.len(),
                valuelen: h.value.len(),
                flags: NGHTTP3_NV_FLAG_NONE as u8,
            })
            .collect();

        let rv = unsafe {
            nghttp3_conn_submit_wt_response(self.inner, stream_id, nvs.as_ptr(), nvs.len())
        };

        check_nghttp3(rv)
    }

    /// Confirms a WebTransport session on the server side.
    ///
    /// Call after `submit_wt_response` when this is done outside the
    /// `end_headers` callback.
    pub fn server_confirm_wt_session(&mut self, session_id: SessionId, ts: u64) -> Result<()> {
        let rv = unsafe { nghttp3_conn_server_confirm_wt_session(self.inner, session_id, ts) };

        check_nghttp3(rv)
    }

    /// Opens a WebTransport data stream.
    ///
    /// Opens a data stream on a WebTransport session. Both bidirectional and
    /// unidirectional streams are supported.
    pub fn open_wt_data_stream(
        &mut self,
        session_id: SessionId,
        stream_id: StreamId,
    ) -> Result<()> {
        // Configure the data-reader callback.
        let dr = nghttp3_data_reader {
            read_data: Some(wt_read_data_callback),
        };

        let rv = unsafe {
            nghttp3_conn_open_wt_data_stream(
                self.inner,
                session_id,
                stream_id,
                &dr,
                ptr::null_mut(),
            )
        };

        check_nghttp3(rv)
    }

    /// Sends data on a WebTransport stream.
    ///
    /// Queues data and asks nghttp3 to resume the stream. The actual bytes are
    /// sent by the next `write_stream()` call.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - Stream ID.
    /// * `data` - Data to send.
    /// * `fin` - Whether to finish the stream.
    pub fn send_wt_stream_data(
        &mut self,
        stream_id: StreamId,
        data: &[u8],
        fin: bool,
    ) -> Result<()> {
        let queue = self
            .user_data
            .wt_send_queues
            .entry(stream_id)
            .or_insert(WtSendQueue {
                data: Vec::new(),
                offset: 0,
                fin: false,
            });

        queue.data.extend_from_slice(data);
        if fin {
            queue.fin = true;
        }

        // Tell nghttp3 that stream data is available.
        self.resume_stream(stream_id)?;

        Ok(())
    }

    /// Closes a WebTransport session.
    ///
    /// Closes the WebTransport session and shuts down related streams.
    pub fn close_wt_session(
        &mut self,
        session_id: SessionId,
        error_code: u32,
        msg: Option<&[u8]>,
    ) -> Result<()> {
        #[cfg(windows)]
        {
            // The current upstream nghttp3 WebTransport close path can
            // dereference an uninitialized session pointer in this sans-io
            // Windows build. Keep the vendored test wrapper from crossing that
            // FFI boundary until the upstream state handling is fixed.
            let _ = (session_id, error_code, msg);
            Err(Error::from_nghttp3(NGHTTP3_ERR_INVALID_STATE))
        }

        #[cfg(not(windows))]
        {
            if unsafe { nghttp3_conn_is_stream_writable2(self.inner, session_id) } == 0 {
                return Err(Error::from_nghttp3(NGHTTP3_ERR_INVALID_STATE));
            }

            let (msg_ptr, msg_len) = match msg {
                Some(m) => (m.as_ptr(), m.len()),
                None => (ptr::null(), 0),
            };

            let rv = unsafe {
                nghttp3_conn_close_wt_session(self.inner, session_id, error_code, msg_ptr, msg_len)
            };

            check_nghttp3(rv)
        }
    }
}

/// Data-reader callback for WebTransport streams.
///
/// Reads outgoing data from `wt_send_queues` in connection user data. Returns
/// WOULDBLOCK when the queue has no data.
unsafe extern "C" fn wt_read_data_callback(
    _conn: *mut nghttp3_conn,
    stream_id: i64,
    vec: *mut nghttp3_vec,
    _veccnt: usize,
    pflags: *mut u32,
    conn_user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> isize {
    if conn_user_data.is_null() || vec.is_null() {
        if !pflags.is_null() {
            unsafe { *pflags = NGHTTP3_DATA_FLAG_NONE };
        }
        return NGHTTP3_ERR_WOULDBLOCK as isize;
    }

    unsafe {
        let user_data = &mut *(conn_user_data as *mut Http3UserData);

        if let Some(queue) = user_data.wt_send_queues.get_mut(&stream_id) {
            let remaining = queue.data.len() - queue.offset;

            if remaining == 0 {
                if queue.fin {
                    *pflags = NGHTTP3_DATA_FLAG_EOF;
                    return 0;
                }
                return NGHTTP3_ERR_WOULDBLOCK as isize;
            }

            (*vec).base = queue.data.as_ptr().add(queue.offset) as *mut u8;
            (*vec).len = remaining;
            queue.offset += remaining;

            if queue.fin {
                *pflags = NGHTTP3_DATA_FLAG_EOF;
            } else {
                *pflags = NGHTTP3_DATA_FLAG_NONE;
            }

            return 1;
        }

        // No queue means no data is currently available.
        *pflags = NGHTTP3_DATA_FLAG_NONE;
        NGHTTP3_ERR_WOULDBLOCK as isize
    }
}

/// Data-reader callback for empty responses.
///
/// Used when sending a header-only response. Sets EOF so the stream is finished
/// with FIN.
unsafe extern "C" fn empty_response_read_data_callback(
    _conn: *mut nghttp3_conn,
    _stream_id: i64,
    _vec: *mut nghttp3_vec,
    _veccnt: usize,
    pflags: *mut u32,
    _conn_user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> isize {
    // Set EOF to finish the stream.
    if !pflags.is_null() {
        unsafe { *pflags = NGHTTP3_DATA_FLAG_EOF };
    }
    // Return no data.
    0
}

/// Data-reader callback for body data.
///
/// Reads body bytes from `StreamBodyData` stored in `stream_user_data`. Shared
/// by request and response body paths.
unsafe extern "C" fn body_read_data_callback(
    _conn: *mut nghttp3_conn,
    _stream_id: i64,
    vec: *mut nghttp3_vec,
    veccnt: usize,
    pflags: *mut u32,
    _conn_user_data: *mut c_void,
    stream_user_data: *mut c_void,
) -> isize {
    if stream_user_data.is_null() || veccnt == 0 || vec.is_null() {
        // Missing user data means EOF.
        if !pflags.is_null() {
            unsafe { *pflags = NGHTTP3_DATA_FLAG_EOF };
        }
        return 0;
    }

    unsafe {
        let body = &mut *(stream_user_data as *mut StreamBodyData);
        let remaining = body.data.len() - body.offset;

        if remaining == 0 {
            // All bytes have been sent; return EOF.
            *pflags = NGHTTP3_DATA_FLAG_EOF;
            return 0;
        }

        // Point nghttp3_vec at the body bytes.
        (*vec).base = body.data.as_ptr().add(body.offset) as *mut u8;
        (*vec).len = remaining;

        // nghttp3 keeps the pointer until the caller reports accepted bytes
        // with add_write_offset. Keep the whole body alive until stream close.
        body.offset += remaining;

        // All bytes were returned, so set EOF.
        *pflags = NGHTTP3_DATA_FLAG_EOF;

        1 // Use one vec.
    }
}

/// Data-reader callback for the request body queue.
///
/// Reads outgoing data from `request_body_queues` in connection user data.
/// Returns WOULDBLOCK when the queue has no data.
unsafe extern "C" fn request_body_queue_read_data_callback(
    _conn: *mut nghttp3_conn,
    stream_id: i64,
    vec: *mut nghttp3_vec,
    _veccnt: usize,
    pflags: *mut u32,
    conn_user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> isize {
    if conn_user_data.is_null() || vec.is_null() {
        if !pflags.is_null() {
            unsafe { *pflags = NGHTTP3_DATA_FLAG_NONE };
        }
        return NGHTTP3_ERR_WOULDBLOCK as isize;
    }

    unsafe {
        let user_data = &mut *(conn_user_data as *mut Http3UserData);

        if let Some(queue) = user_data.request_body_queues.get_mut(&stream_id) {
            let remaining = queue.data.len() - queue.offset;

            if remaining == 0 {
                if queue.fin {
                    *pflags = NGHTTP3_DATA_FLAG_EOF;
                    return 0;
                }
                return NGHTTP3_ERR_WOULDBLOCK as isize;
            }

            (*vec).base = queue.data.as_ptr().add(queue.offset) as *mut u8;
            (*vec).len = remaining;
            queue.offset += remaining;

            if queue.fin {
                *pflags = NGHTTP3_DATA_FLAG_EOF;
            } else {
                *pflags = NGHTTP3_DATA_FLAG_NONE;
            }

            return 1;
        }

        // No queue means no data is currently available.
        *pflags = NGHTTP3_DATA_FLAG_NONE;
        NGHTTP3_ERR_WOULDBLOCK as isize
    }
}

/// Data-reader callback for response bodies kept in connection user data.
unsafe extern "C" fn response_body_queue_read_data_callback(
    _conn: *mut nghttp3_conn,
    stream_id: i64,
    vec: *mut nghttp3_vec,
    _veccnt: usize,
    pflags: *mut u32,
    conn_user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> isize {
    if conn_user_data.is_null() || vec.is_null() {
        if !pflags.is_null() {
            unsafe { *pflags = NGHTTP3_DATA_FLAG_EOF };
        }
        return 0;
    }

    unsafe {
        let user_data = &mut *(conn_user_data as *mut Http3UserData);

        if let Some(queue) = user_data.response_body_queues.get_mut(&stream_id) {
            let remaining = queue.data.len() - queue.offset;

            if remaining == 0 {
                *pflags = NGHTTP3_DATA_FLAG_EOF;
                return 0;
            }

            let chunk_len = remaining.min(RESPONSE_BODY_CHUNK_SIZE);
            (*vec).base = queue.data.as_ptr().add(queue.offset) as *mut u8;
            (*vec).len = chunk_len;
            queue.offset += chunk_len;
            *pflags = if queue.offset == queue.data.len() {
                NGHTTP3_DATA_FLAG_EOF
            } else {
                NGHTTP3_DATA_FLAG_NONE
            };

            return 1;
        }

        *pflags = NGHTTP3_DATA_FLAG_EOF;
        0
    }
}

impl Drop for Http3Connection {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            unsafe { nghttp3_conn_del(self.inner) };
        }
    }
}

/// Creates nghttp3 callbacks.
fn create_callbacks() -> nghttp3_callbacks {
    nghttp3_callbacks {
        acked_stream_data: Some(on_acked_stream_data),
        stream_close: Some(on_stream_close),
        recv_data: Some(on_recv_data),
        deferred_consume: None,
        begin_headers: Some(on_begin_headers),
        recv_header: Some(on_recv_header),
        end_headers: Some(on_end_headers),
        begin_trailers: Some(on_begin_trailers),
        recv_trailer: Some(on_recv_trailer),
        end_trailers: Some(on_end_trailers),
        stop_sending: None,
        end_stream: Some(on_end_stream),
        reset_stream: Some(on_reset_stream),
        shutdown: None,
        recv_settings: None,
        recv_origin: None,
        end_origin: None,
        rand: Some(on_rand),
        recv_settings2: None,
        recv_wt_data: Some(on_recv_wt_data),
        wt_data_stream_open: Some(on_wt_data_stream_open),
        recv_wt_close_session: None,
    }
}

unsafe extern "C" fn on_acked_stream_data(
    _conn: *mut nghttp3_conn,
    _stream_id: i64,
    _datalen: u64,
    _conn_user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    0
}

unsafe extern "C" fn on_stream_close(
    _conn: *mut nghttp3_conn,
    stream_id: i64,
    app_error_code: u64,
    conn_user_data: *mut c_void,
    stream_user_data: *mut c_void,
) -> c_int {
    // Free stream_user_data when it is StreamBodyData.
    if !stream_user_data.is_null() {
        unsafe {
            drop(Box::from_raw(stream_user_data as *mut StreamBodyData));
        }
    }

    if conn_user_data.is_null() {
        return 0;
    }

    unsafe {
        let user_data = &mut *(conn_user_data as *mut Http3UserData);

        // Clean up send queues.
        user_data.wt_send_queues.remove(&stream_id);
        user_data.request_body_queues.remove(&stream_id);
        user_data.response_body_queues.remove(&stream_id);

        if !user_data.events.is_null() {
            (*user_data.events).push_back(Http3Event::StreamClose {
                stream_id,
                error_code: app_error_code,
            });
        }
    }

    0
}

unsafe extern "C" fn on_recv_data(
    _conn: *mut nghttp3_conn,
    stream_id: i64,
    data: *const u8,
    datalen: usize,
    conn_user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    if conn_user_data.is_null() {
        return 0;
    }

    unsafe {
        let user_data = &*(conn_user_data as *const Http3UserData);
        if !user_data.events.is_null() {
            let data_slice = std::slice::from_raw_parts(data, datalen);
            (*user_data.events).push_back(Http3Event::Data {
                stream_id,
                data: data_slice.to_vec(),
            });
        }
    }

    0
}

unsafe extern "C" fn on_begin_headers(
    _conn: *mut nghttp3_conn,
    stream_id: i64,
    conn_user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    if conn_user_data.is_null() {
        return 0;
    }

    unsafe {
        let user_data = &*(conn_user_data as *const Http3UserData);
        if !user_data.events.is_null() {
            (*user_data.events).push_back(Http3Event::HeadersBegin { stream_id });
        }
    }

    0
}

unsafe extern "C" fn on_recv_header(
    _conn: *mut nghttp3_conn,
    stream_id: i64,
    _token: i32,
    name: *mut nghttp3_rcbuf,
    value: *mut nghttp3_rcbuf,
    _flags: u8,
    conn_user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    if conn_user_data.is_null() {
        return 0;
    }

    unsafe {
        let user_data = &*(conn_user_data as *const Http3UserData);
        if !user_data.events.is_null() {
            let name_vec = nghttp3_rcbuf_get_buf(name);
            let value_vec = nghttp3_rcbuf_get_buf(value);

            let name_slice = std::slice::from_raw_parts(name_vec.base, name_vec.len);
            let value_slice = std::slice::from_raw_parts(value_vec.base, value_vec.len);

            (*user_data.events).push_back(Http3Event::Header {
                stream_id,
                header: Header::new(name_slice.to_vec(), value_slice.to_vec()),
            });
        }
    }

    0
}

unsafe extern "C" fn on_end_headers(
    _conn: *mut nghttp3_conn,
    stream_id: i64,
    fin: c_int,
    conn_user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    if conn_user_data.is_null() {
        return 0;
    }

    unsafe {
        let user_data = &*(conn_user_data as *const Http3UserData);
        if !user_data.events.is_null() {
            (*user_data.events).push_back(Http3Event::HeadersEnd {
                stream_id,
                fin: fin != 0,
            });
        }
    }

    0
}

unsafe extern "C" fn on_begin_trailers(
    _conn: *mut nghttp3_conn,
    stream_id: i64,
    conn_user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    if conn_user_data.is_null() {
        return 0;
    }

    unsafe {
        let user_data = &*(conn_user_data as *const Http3UserData);
        if !user_data.events.is_null() {
            (*user_data.events).push_back(Http3Event::TrailersBegin { stream_id });
        }
    }

    0
}

unsafe extern "C" fn on_recv_trailer(
    _conn: *mut nghttp3_conn,
    stream_id: i64,
    _token: i32,
    name: *mut nghttp3_rcbuf,
    value: *mut nghttp3_rcbuf,
    _flags: u8,
    conn_user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    if conn_user_data.is_null() {
        return 0;
    }

    unsafe {
        let user_data = &*(conn_user_data as *const Http3UserData);
        if !user_data.events.is_null() {
            let name_vec = nghttp3_rcbuf_get_buf(name);
            let value_vec = nghttp3_rcbuf_get_buf(value);

            let name_slice = std::slice::from_raw_parts(name_vec.base, name_vec.len);
            let value_slice = std::slice::from_raw_parts(value_vec.base, value_vec.len);

            (*user_data.events).push_back(Http3Event::Trailer {
                stream_id,
                header: Header::new(name_slice.to_vec(), value_slice.to_vec()),
            });
        }
    }

    0
}

unsafe extern "C" fn on_end_trailers(
    _conn: *mut nghttp3_conn,
    stream_id: i64,
    _fin: c_int,
    conn_user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    if conn_user_data.is_null() {
        return 0;
    }

    unsafe {
        let user_data = &*(conn_user_data as *const Http3UserData);
        if !user_data.events.is_null() {
            (*user_data.events).push_back(Http3Event::TrailersEnd { stream_id });
        }
    }

    0
}

unsafe extern "C" fn on_end_stream(
    _conn: *mut nghttp3_conn,
    stream_id: i64,
    conn_user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    if conn_user_data.is_null() {
        return 0;
    }

    unsafe {
        let user_data = &*(conn_user_data as *const Http3UserData);
        if !user_data.events.is_null() {
            (*user_data.events).push_back(Http3Event::StreamEnd { stream_id });
        }
    }

    0
}

unsafe extern "C" fn on_reset_stream(
    _conn: *mut nghttp3_conn,
    stream_id: i64,
    app_error_code: u64,
    conn_user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    if conn_user_data.is_null() {
        return 0;
    }

    unsafe {
        let user_data = &*(conn_user_data as *const Http3UserData);
        if !user_data.events.is_null() {
            (*user_data.events).push_back(Http3Event::Reset {
                stream_id,
                error_code: app_error_code,
            });
        }
    }

    0
}

unsafe extern "C" fn on_rand(dest: *mut u8, destlen: usize) {
    if dest.is_null() || destlen == 0 {
        return;
    }

    unsafe {
        let slice = std::slice::from_raw_parts_mut(dest, destlen);
        let _ = aws_lc_rs::rand::fill(slice);
    }
}

unsafe extern "C" fn on_recv_wt_data(
    _conn: *mut nghttp3_conn,
    session_id: i64,
    stream_id: i64,
    data: *const u8,
    datalen: usize,
    conn_user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    if conn_user_data.is_null() {
        return 0;
    }

    unsafe {
        let user_data = &*(conn_user_data as *const Http3UserData);
        if !user_data.events.is_null() {
            let data_slice = std::slice::from_raw_parts(data, datalen);
            (*user_data.events).push_back(Http3Event::WebTransportData {
                session_id,
                stream_id,
                data: data_slice.to_vec(),
            });
        }
    }

    0
}

/// Callback for WebTransport data stream open events.
///
/// Called when a remote stream is identified as a WebTransport data stream
/// (nghttp3 1.12.0+ WebTransport API). Data itself is delivered through
/// `recv_wt_data`, so this callback is only a notification. nghttp3 calls this
/// field assuming it is non-NULL, so always set a function to avoid undefined
/// behavior from layout mismatches.
unsafe extern "C" fn on_wt_data_stream_open(
    _conn: *mut nghttp3_conn,
    _session_id: i64,
    _stream_id: i64,
    _conn_user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    0
}
