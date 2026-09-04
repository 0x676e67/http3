//! Compiles the native nghttp3/ngtcp2 benchmark adapter through Cargo.

use std::{env, error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/native/client.c");

    let target_os = env::var("CARGO_CFG_TARGET_OS")?;
    if target_os != "windows" && target_os != "linux" {
        return Err(format!(
            "the HTTP/3 Client benchmark supports only Windows and Linux, not {target_os}"
        )
        .into());
    }
    let host = env::var("HOST")?;
    let target = env::var("TARGET")?;
    if host != target {
        return Err(format!(
            "the native benchmark Client must run on the build host; cross-compiling from {host} \
             to {target} is unsupported"
        )
        .into());
    }
    let target_env = env::var("CARGO_CFG_TARGET_ENV")?;
    if target_os == "windows" && target_env != "msvc" {
        return Err(format!(
            "the Windows HTTP/3 Client benchmark supports the MSVC toolchain, not {target_env}"
        )
        .into());
    }

    let mut build = cc::Build::new();
    build
        .file("src/native/client.c")
        .include(required_path("DEP_NGTCP2_INCLUDE")?)
        .include(required_path("DEP_NGHTTP3_INCLUDE")?)
        .include(required_path("DEP_AWS_LC_0_44_0_INCLUDE")?)
        .define("NGTCP2_STATICLIB", None)
        .define("NGHTTP3_STATICLIB", None)
        .opt_level(3)
        .warnings(true)
        .warnings_into_errors(true);

    if target_os == "windows" {
        build
            .define("WIN32_LEAN_AND_MEAN", None)
            .define("_WIN32_WINNT", Some("0x0A00"))
            .define("_CRT_SECURE_NO_WARNINGS", None)
            .flag_if_supported("/std:c11")
            .flag_if_supported("/utf-8")
            .flag("/external:anglebrackets")
            .flag_if_supported("/external:W0");
    } else {
        build
            .define("_GNU_SOURCE", None)
            .define("_POSIX_C_SOURCE", Some("200809L"))
            .flag_if_supported("-std=c11");
    }

    build.compile("http3_bench_nghttp3_client");

    if target_os == "windows" {
        for library in ["ws2_32", "bcrypt", "crypt32", "advapi32", "userenv"] {
            println!("cargo:rustc-link-lib={library}");
        }
    } else {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=dl");
    }
    Ok(())
}

fn required_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("Cargo did not expose {name}").into())
}
