//! Isolated native Client executable for nghttp3 with the ngtcp2 backend.

fn main() {
    match http3_bench::run_nghttp3_client(std::env::args_os().skip(1)) {
        Ok(0) => {}
        Ok(status) => std::process::exit(status),
        Err(error) => {
            eprintln!("nghttp3 benchmark client failed: {error:#}");
            std::process::exit(1);
        }
    }
}
