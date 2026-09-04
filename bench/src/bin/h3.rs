//! Isolated Client executable for the fixed upstream `h3` implementation.

http3_bench::client_adapter!(Client, h3, h3_quinn, "h3");

fn main() {
    if let Err(error) = http3_bench::run_client::<Client>(std::env::args().skip(1)) {
        eprintln!("h3 benchmark client failed: {error:#}");
        std::process::exit(1);
    }
}
