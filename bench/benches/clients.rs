//! Criterion controller and isolated HTTP/3 benchmark process roles.

use std::{env, ffi::OsString};

use anyhow::{Context, Result};
use criterion::{Criterion, criterion_group};
use http3_bench::case::Http3Library;

mod child;
mod runner;

use child::{CHILD_MARKER, ChildRole};

http3_bench::client_adapter!(Http3Client, http3, http3_quic, "http3");
http3_bench::client_adapter!(H3Client, h3, h3_quinn, "h3");

fn clients(criterion: &mut Criterion) {
    runner::run(criterion)
        .unwrap_or_else(|error| panic!("HTTP/3 Client benchmark failed: {error:#}"));
}

criterion_group!(benches, clients);

fn main() {
    match run() {
        Ok(0) => {}
        Ok(status) => std::process::exit(status),
        Err(error) => {
            eprintln!("HTTP/3 benchmark process failed: {error:#}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32> {
    let mut args = env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new(CHILD_MARKER)) {
        benches();
        Criterion::default().configure_from_args().final_summary();
        return Ok(0);
    }

    let role = args.next().context("missing internal benchmark role")?;
    run_child(ChildRole::parse(&role)?, args)
}

fn run_child(role: ChildRole, args: impl Iterator<Item = OsString>) -> Result<i32> {
    match role {
        ChildRole::Client(Http3Library::Http3) => {
            http3_bench::run_client::<Http3Client>(string_args(args)?.into_iter())
                .context("http3 benchmark client failed")?;
            Ok(0)
        }
        ChildRole::Client(Http3Library::H3) => {
            http3_bench::run_client::<H3Client>(string_args(args)?.into_iter())
                .context("h3 benchmark client failed")?;
            Ok(0)
        }
        ChildRole::Client(Http3Library::Nghttp3) => {
            http3_bench::run_nghttp3_client(args).context("nghttp3 benchmark client failed")
        }
        ChildRole::Server => {
            http3_bench::run_server(string_args(args)?.into_iter())
                .context("HTTP/3 benchmark server failed")?;
            Ok(0)
        }
    }
}

fn string_args(args: impl Iterator<Item = OsString>) -> Result<Vec<String>> {
    args.map(|argument| {
        argument.into_string().map_err(|argument| {
            anyhow::anyhow!("internal benchmark argument is not Unicode: {argument:?}")
        })
    })
    .collect()
}
