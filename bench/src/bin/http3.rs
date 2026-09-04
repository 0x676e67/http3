//! Isolated Client executable for this repository's `http3` implementation.

http3_bench::client_adapter!(Client, http3, http3_quic, "http3");

fn main() {
    if let Err(error) = http3_bench::run_client::<Client>(std::env::args().skip(1)) {
        eprintln!("http3 benchmark client failed: {error:#}");
        std::process::exit(1);
    }
}
