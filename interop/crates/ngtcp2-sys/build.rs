use std::path::PathBuf;
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

/// Reads external dependency metadata from Cargo.toml.
fn read_external_dependency(name: &str) -> toml::Table {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let cargo_toml = std::fs::read_to_string(manifest_dir.join("Cargo.toml"))
        .expect("Failed to read Cargo.toml");
    let parsed = toml::from_str::<toml::Table>(&cargo_toml).expect("Failed to parse Cargo.toml");

    parsed
        .get("package")
        .and_then(|p| p.get("metadata"))
        .and_then(|m| m.get("external-dependencies"))
        .and_then(|e| e.get(name))
        .and_then(|d| d.as_table())
        .cloned()
        .unwrap_or_else(|| panic!("Missing [package.metadata.external-dependencies.{name}]"))
}

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Read metadata from Cargo.toml.
    let dep = read_external_dependency("ngtcp2");
    let git_url = dep
        .get("git")
        .and_then(|v| v.as_str())
        .expect("Missing 'git' field in ngtcp2 dependency");
    let branch = dep.get("branch").and_then(|v| v.as_str());
    let version = dep.get("version").and_then(|v| v.as_str());

    // Clone ngtcp2.
    let ngtcp2_dir = out_dir.join("ngtcp2");
    if !ngtcp2_dir.exists() {
        // git clone
        let status = Command::new("git")
            .args(["clone", git_url, ngtcp2_dir.to_str().unwrap()])
            .status()
            .expect("Failed to execute git clone");
        if !status.success() {
            panic!("Failed to clone ngtcp2");
        }

        // Check out the branch or version tag.
        if let Some(branch_name) = branch {
            let status = Command::new("git")
                .current_dir(&ngtcp2_dir)
                .args(["checkout", branch_name])
                .status()
                .expect("Failed to execute git checkout");
            if !status.success() {
                panic!("Failed to checkout branch {branch_name}");
            }
        } else if let Some(ver) = version {
            let tag = format!("v{ver}");
            let status = Command::new("git")
                .current_dir(&ngtcp2_dir)
                .args(["checkout", &tag])
                .status()
                .expect("Failed to execute git checkout");
            if !status.success() {
                panic!("Failed to checkout tag {tag}");
            }
        }
    }

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

    #[cfg(feature = "overwrite")]
    overwrite_bindgen(&out_dir);
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

#[cfg(feature = "overwrite")]
fn overwrite_bindgen(out_dir: &PathBuf) {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    // Build include directory where version.h is generated.
    let ngtcp2_installed_include = out_dir.join("include");
    // Source include directory where ngtcp2.h lives.
    let ngtcp2_source_include = out_dir.join("ngtcp2/lib/includes");
    // aws-lc include directory where openssl/ssl.h lives.
    let aws_lc_links = detect_aws_lc_links_name();
    let include_env = format!("DEP_{}_INCLUDE", aws_lc_links.to_uppercase());
    let aws_lc_include =
        std::env::var(&include_env).unwrap_or_else(|_| panic!("{include_env} not set"));

    bindgen::Builder::default()
        .header(manifest_dir.join("src/wrapper.h").to_str().unwrap())
        .clang_arg(format!("-I{}", ngtcp2_installed_include.display()))
        .clang_arg(format!("-I{}", ngtcp2_source_include.display()))
        .clang_arg(format!("-I{}", aws_lc_include))
        .allowlist_function("ngtcp2_.*")
        .allowlist_type("ngtcp2_.*")
        .allowlist_var("NGTCP2_.*")
        .generate()
        .expect("Failed to generate ngtcp2 bindings")
        .write_to_file(manifest_dir.join("src/bindings.rs"))
        .expect("Failed to write ngtcp2 bindings");
}
