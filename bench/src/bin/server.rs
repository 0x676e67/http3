//! Child Server executable shared by all compared HTTP/3 Clients.

fn main() {
    if let Err(error) = http3_bench::run_server(std::env::args().skip(1)) {
        eprintln!("http3 benchmark server failed: {error:#}");
        std::process::exit(1);
    }
}
