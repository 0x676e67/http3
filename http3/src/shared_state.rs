//! Shared state for an HTTP/3 connection.

use std::{
    borrow::Cow,
    sync::{
        Arc, OnceLock,
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
    changed: Arc<tokio::sync::Notify>,
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            settings: OnceLock::new(),
            connection_error: OnceLock::new(),
            closing: AtomicBool::new(false),
            waker: AtomicWaker::new(),
            peer_goaway: AtomicU64::new(u64::MAX),
            changed: Arc::default(),
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
        let err = self
            .shared_state()
            .connection_error
            .get_or_init(move || error);
        self.shared_state().changed.notify_waiters();
        err.clone()
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
        self.shared_state().changed.notify_waiters();
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
    pub(crate) fn notified(&self) -> tokio::sync::futures::OwnedNotified {
        self.changed.clone().notified_owned()
    }

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

    pub(crate) fn set_peer_goaway(&self, boundary: StreamId) {
        if self
            .peer_goaway
            .fetch_min(boundary.into_inner(), Ordering::AcqRel)
            > boundary.into_inner()
        {
            self.changed.notify_waiters();
        }
    }

    pub(crate) async fn wait_closing(&self) {
        loop {
            // notify_waiters records events even before Notified's first poll.
            let changed = self.changed.notified();
            if self.is_closing() || self.get_conn_error().is_some() {
                return;
            }
            changed.await;
        }
    }

    pub(crate) async fn wait_rejected(&self, stream_id: StreamId) -> StreamError {
        loop {
            let changed = self.changed.notified();
            if let Some(error) = self.request_error(stream_id) {
                return error;
            }
            changed.await;
        }
    }
}

impl crate::error::connection_error_creators::CloseStream for SharedState {}
