use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Detects the aws-lc-sys links name from Cargo-provided environment variables.
///
/// Cargo sets `DEP_{LINKS}_INCLUDE` based on a dependency crate's `links`
/// attribute, so this keeps working when the exact links name changes.
fn detect_aws_lc_links_name() -> String {
    for (key, _) in std::env::vars() {
        if key.starts_with("DEP_AWS_LC_") && key.ends_with("_INCLUDE") {
            // "DEP_AWS_LC_0_38_0_INCLUDE" → "aws_lc_0_38_0"
            let middle = key
                .strip_prefix("DEP_")
                .unwrap()
                .strip_suffix("_INCLUDE")
                .unwrap();
            return middle.to_lowercase();
        }
    }
    panic!("DEP_AWS_LC_*_INCLUDE not found - aws-lc-sys dependency required");
}

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let ngtcp2_dir = prepare_submodule_source("ngtcp2", &manifest_dir, &out_dir);

    patch_ngtcp2_for_msvc(&ngtcp2_dir);

    // Auto-detect the aws-lc-sys links name.
    let aws_lc_links = detect_aws_lc_links_name();
    let include_env = format!("DEP_{}_INCLUDE", aws_lc_links.to_uppercase());
    let aws_lc_include = std::env::var(&include_env)
        .unwrap_or_else(|_| panic!("{include_env} not set - aws-lc-sys dependency required"));

    // The parent of the include path is OUT_DIR. Libraries are under
    // {OUT_DIR}/build/artifacts/.
    let aws_lc_out_dir = PathBuf::from(&aws_lc_include)
        .parent()
        .expect("Failed to get parent directory of include path")
        .to_path_buf();
    let aws_lc_lib_dir = aws_lc_out_dir.join("build").join("artifacts");

    // Build ngtcp2 with aws-lc. Windows/MSVC produces .lib files; other
    // platforms produce lib*.a files.
    let (ssl_lib, crypto_lib) = if cfg!(target_env = "msvc") {
        (
            aws_lc_lib_dir.join(format!("{}_ssl.lib", aws_lc_links)),
            aws_lc_lib_dir.join(format!("{}_crypto.lib", aws_lc_links)),
        )
    } else {
        (
            aws_lc_lib_dir.join(format!("lib{}_ssl.a", aws_lc_links)),
            aws_lc_lib_dir.join(format!("lib{}_crypto.a", aws_lc_links)),
        )
    };
    // CMake treats Windows backslashes as invalid escapes here, so use forward
    // slashes.
    let ssl_lib_str = ssl_lib.to_str().unwrap().replace('\\', "/");
    let crypto_lib_str = crypto_lib.to_str().unwrap().replace('\\', "/");
    let boringssl_libraries = format!("{ssl_lib_str};{crypto_lib_str}");

    let mut ngtcp2_config = cmake::Config::new(&ngtcp2_dir);
    ngtcp2_config
        .define("ENABLE_STATIC_LIB", "ON")
        .define("ENABLE_SHARED_LIB", "OFF")
        .define("ENABLE_LIB_ONLY", "ON")
        .define("BUILD_TESTING", "OFF")
        .define("ENABLE_OPENSSL", "OFF")
        .define("ENABLE_BORINGSSL", "ON")
        .define("BORINGSSL_INCLUDE_DIR", &aws_lc_include)
        .define("BORINGSSL_LIBRARIES", &boringssl_libraries);
    configure_msvc_runtime(&mut ngtcp2_config);

    let ngtcp2_dst = ngtcp2_config.build();

    // Library path.
    let lib_dir = if ngtcp2_dst.join("lib64").exists() {
        ngtcp2_dst.join("lib64")
    } else {
        ngtcp2_dst.join("lib")
    };

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=ngtcp2");
    println!("cargo:rustc-link-lib=static=ngtcp2_crypto_boringssl");

    // Pass metadata to dependent crates.
    println!("cargo:include={}/include", ngtcp2_dst.display());

    generate_bindings(
        &ngtcp2_dst.join("include"),
        &ngtcp2_dir.join("lib/includes"),
        &PathBuf::from(&aws_lc_include),
        &out_dir.join("bindings.rs"),
    );
}

fn configure_msvc_runtime(config: &mut cmake::Config) {
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        return;
    }

    // Rust uses the release MSVC runtime in every Cargo profile. CMake's Debug
    // default is MSVCRTD, which conflicts with Rust's runtime at final link.
    let target_features = std::env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    let runtime = if target_features
        .split(',')
        .any(|feature| feature == "crt-static")
    {
        "MultiThreaded"
    } else {
        "MultiThreadedDLL"
    };
    config.define("CMAKE_MSVC_RUNTIME_LIBRARY", runtime);
}

fn prepare_submodule_source(name: &str, manifest_dir: &Path, out_dir: &Path) -> PathBuf {
    let submodule_dir = manifest_dir.join("deps").join(name);

    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("../../..").join(".gitmodules").display()
    );
    println!("cargo:rerun-if-changed={}", submodule_dir.display());

    ensure_submodule_initialized(&submodule_dir, manifest_dir);

    let build_dir = out_dir.join(name);
    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove old ngtcp2 build source");
    }
    copy_dir_all(&submodule_dir, &build_dir).expect("Failed to copy ngtcp2 submodule");
    build_dir
}

fn ensure_submodule_initialized(submodule_dir: &Path, manifest_dir: &Path) {
    if submodule_source_ready(submodule_dir) {
        return;
    }

    let relative = submodule_dir
        .strip_prefix(manifest_dir)
        .expect("submodule path should be under manifest dir")
        .to_string_lossy()
        .replace('\\', "/");

    let status = Command::new("git")
        .current_dir(manifest_dir)
        .args([
            "submodule",
            "update",
            "--init",
            "--recursive",
            "--",
            &relative,
        ])
        .status()
        .expect("Failed to execute git submodule update");
    if !status.success() {
        panic!("Failed to initialize {relative} submodule");
    }
}

fn submodule_source_ready(submodule_dir: &Path) -> bool {
    // The crates.io package carries only the lib-only CMake inputs. Check the
    // paths used by this build instead of every upstream test submodule.
    submodule_dir.join("CMakeLists.txt").exists()
        && required_paths_ready(
            submodule_dir,
            &[
                "crypto/boringssl/CMakeLists.txt",
                "crypto/includes/CMakeLists.txt",
                "lib/CMakeLists.txt",
                "third-party/CMakeLists.txt",
            ],
        )
}

fn required_paths_ready(submodule_dir: &Path, paths: &[&str]) -> bool {
    paths.iter().all(|path| submodule_dir.join(path).exists())
}

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_name = entry.file_name();
        if file_name == ".git" {
            continue;
        }

        let src_path = entry.path();
        let dst_path = dst.join(file_name);
        if entry.file_type()?.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn patch_ngtcp2_for_msvc(ngtcp2_dir: &std::path::Path) {
    if !cfg!(target_env = "msvc") {
        return;
    }

    // Apply source patches only to the CMake checkout in OUT_DIR. These are
    // Windows build fixes for the vendored test dependency, not changes to the
    // Rust wrapper's public API.
    patch_ngtcp2_minmax_for_msvc(ngtcp2_dir);
    patch_ngtcp2_format_for_msvc(ngtcp2_dir);
}

fn patch_ngtcp2_minmax_for_msvc(ngtcp2_dir: &std::path::Path) {
    let macro_path = ngtcp2_dir.join("lib/ngtcp2_macro.h");
    let mut contents = std::fs::read_to_string(&macro_path).expect("Failed to read ngtcp2_macro.h");
    let marker = "HTTP3_RS_MSVC_NGTCP2_MINMAX_PATCH";

    if contents.contains(marker) {
        return;
    }

    let patch = format!(
        r#"

/* {marker}
 * MSVC treats plain char as compatible with signed char in _Generic
 * associations, so ngtcp2's upstream generic min/max macros fail with C7700.
 * The current call sites pass variables or simple expressions, so a portable
 * comparison macro is enough for the Windows build.
 */
#if defined(_MSC_VER)
#  undef ngtcp2_max
#  undef ngtcp2_min
#  define ngtcp2_max(A, B) ((A) < (B) ? (B) : (A))
#  define ngtcp2_min(A, B) ((A) < (B) ? (A) : (B))
#endif
"#
    );

    contents = contents.replace(
        "#endif /* !defined(NGTCP2_MACRO_H) */",
        &format!("{patch}\n#endif /* !defined(NGTCP2_MACRO_H) */"),
    );

    std::fs::write(macro_path, contents).expect("Failed to patch ngtcp2_macro.h");
}

fn patch_ngtcp2_format_for_msvc(ngtcp2_dir: &std::path::Path) {
    let fmt_path = ngtcp2_dir.join("lib/ngtcp2_fmt.h");
    let mut contents = std::fs::read_to_string(&fmt_path).expect("Failed to read ngtcp2_fmt.h");
    let marker = "HTTP3_RS_MSVC_NGTCP2_FMT_PATCH";
    let original = contents.clone();

    contents = contents
        .lines()
        .filter(|line| {
            !(line.contains("signed char: ngtcp2_fmt_hex_signed_char_init")
                || line.contains("signed char: ngtcp2_fmt_hexw_signed_char_init")
                || line.contains("signed char: ngtcp2_fmt_write_int64"))
        })
        .collect::<Vec<_>>()
        .join("\n");

    if !contents.contains(marker) {
        let note = format!(
            "/* {marker}\n * MSVC's _Generic handling treats plain char as compatible with signed\n * char.  Dropping the signed-char associations keeps ngtcp2's formatter\n * usable on Windows without changing the public ngtcp2 API.\n */\n"
        );
        contents = contents.replace("#define hex(T)", &format!("{note}#define hex(T)"));
    }

    if contents != original {
        std::fs::write(fmt_path, contents).expect("Failed to patch ngtcp2_fmt.h");
    }
}

fn generate_bindings(
    installed_include: &std::path::Path,
    source_include: &std::path::Path,
    aws_lc_include: &std::path::Path,
    output: &std::path::Path,
) {
    let target = std::env::var("TARGET").expect("TARGET not set by Cargo");

    // Bindings are generated for the Cargo target, not the build host. This
    // keeps bindgen layout tests correct for 32-bit CI targets.
    bindgen::Builder::default()
        .header(installed_include.join("ngtcp2/ngtcp2.h").to_str().unwrap())
        .header(
            installed_include
                .join("ngtcp2/ngtcp2_crypto.h")
                .to_str()
                .unwrap(),
        )
        .header(
            installed_include
                .join("ngtcp2/ngtcp2_crypto_boringssl.h")
                .to_str()
                .unwrap(),
        )
        .clang_arg(format!("--target={target}"))
        .clang_arg(format!("-I{}", installed_include.display()))
        .clang_arg(format!("-I{}", source_include.display()))
        .clang_arg(format!("-I{}", aws_lc_include.display()))
        .allowlist_function("ngtcp2_.*")
        .allowlist_type("ngtcp2_.*")
        .allowlist_var("NGTCP2_.*")
        .generate()
        .expect("Failed to generate ngtcp2 bindings")
        .write_to_file(output)
        .expect("Failed to write ngtcp2 bindings");
}
