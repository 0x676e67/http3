//! Shared state for an HTTP/3 connection.

use std::{
    borrow::Cow,
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use futures_util::task::AtomicWaker;

use crate::{
    config::Settings,
    error::{
        StreamError, connection_error_creators::convert_to_connection_error,
        internal_error::ErrorOrigin,
    },
    quic::StreamId,
};

/// State shared by an HTTP/3 connection and its streams.
#[derive(Debug)]
pub struct SharedState {
    /// The settings, sent by the peer
    settings: OnceLock<Settings>,
    /// The connection error
    connection_error: OnceLock<ErrorOrigin>,
    /// The connection is closing
    closing: AtomicBool,
    /// Waker for the connection
    waker: AtomicWaker,
    // u64::MAX is outside the QUIC stream ID space.
    peer_goaway: AtomicU64,
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            settings: OnceLock::new(),
            connection_error: OnceLock::new(),
            closing: AtomicBool::new(false),
            waker: AtomicWaker::new(),
            peer_goaway: AtomicU64::new(u64::MAX),
        }
    }
}

impl ConnectionState for SharedState {
    fn shared_state(&self) -> &SharedState {
        self
    }
}

/// This trait can be implemented for all types which have a shared state
pub trait ConnectionState {
    /// Get the shared state
    fn shared_state(&self) -> &SharedState;
    /// Get the connection error if the connection is in error state because of another task
    ///
    /// Return the error as an Err variant if it is set in order to allow using ? in the calling
    /// function
    fn get_conn_error(&self) -> Option<ErrorOrigin> {
        self.shared_state().connection_error.get().cloned()
    }

    /// tries to set the connection error
    fn set_conn_error(&self, error: ErrorOrigin) -> ErrorOrigin {
        self.shared_state()
            .connection_error
            .get_or_init(move || error)
            .clone()
    }

    /// set the connection error and wake the connection
    fn set_conn_error_and_wake<T: Into<ErrorOrigin>>(&self, error: T) -> ErrorOrigin {
        let err = self.set_conn_error(error.into());
        self.waker().wake();
        err
    }

    /// Get the settings
    fn settings(&self) -> Cow<'_, Settings> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //# Each endpoint SHOULD use
        //# these initial values to send messages before the peer's SETTINGS
        //# frame has arrived, as packets carrying the settings can be lost or
        //# delayed.
        self.shared_state()
            .settings
            .get()
            .map(Cow::Borrowed)
            .unwrap_or_default()
    }
    /// Set the connection to closing
    fn set_closing(&self) {
        self.shared_state().closing.store(true, Ordering::Release);
    }
    /// Returns the boundary of the peer's GOAWAY, once one was received.
    ///
    /// For a client this is the lowest request stream ID the server will not
    /// process; requests at or above it fail with
    /// [`StreamError::GoawayRejected`] when next polled and may be retried on
    /// another connection. See [RFC 9114, Section 5.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-5.2).
    #[cfg(any(test, feature = "unstable"))]
    fn peer_goaway(&self) -> Option<StreamId> {
        StreamId::try_from(self.shared_state().peer_goaway.load(Ordering::Acquire)).ok()
    }
    /// Check if the connection is closing
    fn is_closing(&self) -> bool {
        self.shared_state().closing.load(Ordering::Acquire)
    }
    /// Set the settings
    fn set_settings(&self, settings: Settings) {
        let _ = self.shared_state().settings.set(settings);
    }

    /// Returns the waker for the connection
    fn waker(&self) -> &AtomicWaker {
        &self.shared_state().waker
    }
}

impl SharedState {
    /// Returns the published error that prevents this client request from continuing.
    ///
    /// For a client-initiated bidirectional `stream_id` at or above the validated
    /// peer GOAWAY boundary, returns [`StreamError::GoawayRejected`], even if a
    /// connection error has also been published. Otherwise returns that connection
    /// error, or `None` if neither condition applies. Closing alone does not reject
    /// an existing request below the boundary.
    ///
    /// This is a state snapshot checked around each poll of a request
    /// operation; nothing is woken when the state changes, and the transport
    /// stream is not cancelled here. See [RFC 9114, Section 5.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-5.2).
    pub(crate) fn request_error(&self, stream_id: StreamId) -> Option<StreamError> {
        let boundary = self.peer_goaway.load(Ordering::Acquire);
        if stream_id.into_inner() >= boundary {
            // Only validated server GOAWAY IDs are stored here.
            if let Ok(boundary) = StreamId::try_from(boundary) {
                return Some(StreamError::GoawayRejected {
                    stream_id,
                    boundary,
                });
            }
        }
        self.get_conn_error()
            .map(convert_to_connection_error)
            .map(StreamError::ConnectionError)
    }

    /// Publishes the first request stream ID excluded by a server's GOAWAY.
    ///
    /// The connection driver must first validate that `boundary` identifies a
    /// client-initiated bidirectional stream and does not increase a previous
    /// GOAWAY ID. Only the smallest boundary is retained. Request operations
    /// observe it through [`Self::request_error`] on their next poll; nothing
    /// is woken here, and neither the closing flag nor transport streams change.
    ///
    /// See [RFC 9114, Section 5.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-5.2)
    /// and [Section 7.2.6](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.6).
    pub(crate) fn set_peer_goaway(&self, boundary: StreamId) {
        self.peer_goaway
            .fetch_min(boundary.into_inner(), Ordering::AcqRel);
    }
}

impl crate::error::connection_error_creators::CloseStream for SharedState {}
