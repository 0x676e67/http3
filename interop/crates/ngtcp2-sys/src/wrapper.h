// ngtcp2 core API implementing RFC 9000 QUIC.
// Provides the main QUIC features: connection management, stream operations,
// and packet send/receive.
#include <ngtcp2/ngtcp2.h>

// QUIC-TLS integration API from RFC 9001.
// Provides TLS-backend-independent hooks for combining QUIC with TLS 1.3,
// including key derivation and encryption-level management.
#include <ngtcp2/ngtcp2_crypto.h>

// BoringSSL/aws-lc specific QUIC-TLS implementation.
// Implements the abstract ngtcp2_crypto.h interface for BoringSSL. Required
// here because the wrapper uses aws-lc-sys as its TLS library.
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
