use std::path::PathBuf;
use std::process::Command;

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
    let dep = read_external_dependency("nghttp3");
    let git_url = dep
        .get("git")
        .and_then(|v| v.as_str())
        .expect("Missing 'git' field in nghttp3 dependency");
    // Switch nghttp3 to a version tag once the WebTransport branch is released.
    let branch = dep.get("branch").and_then(|v| v.as_str());
    let version = dep.get("version").and_then(|v| v.as_str());

    // Clone nghttp3.
    let nghttp3_dir = out_dir.join("nghttp3");
    if !nghttp3_dir.exists() {
        // git clone
        let status = Command::new("git")
            .args(["clone", git_url, nghttp3_dir.to_str().unwrap()])
            .status()
            .expect("Failed to execute git clone");
        if !status.success() {
            panic!("Failed to clone nghttp3");
        }

        // Check out the branch or version tag.
        if let Some(branch_name) = branch {
            let status = Command::new("git")
                .current_dir(&nghttp3_dir)
                .args(["checkout", branch_name])
                .status()
                .expect("Failed to execute git checkout");
            if !status.success() {
                panic!("Failed to checkout branch {branch_name}");
            }
        } else if let Some(ver) = version {
            let tag = format!("v{ver}");
            let status = Command::new("git")
                .current_dir(&nghttp3_dir)
                .args(["checkout", &tag])
                .status()
                .expect("Failed to execute git checkout");
            if !status.success() {
                panic!("Failed to checkout tag {tag}");
            }
        }

        // Initialize and update submodules.
        let status = Command::new("git")
            .current_dir(&nghttp3_dir)
            .args(["submodule", "update", "--init", "--recursive"])
            .status()
            .expect("Failed to execute git submodule update");
        if !status.success() {
            panic!("Failed to update submodules");
        }
    }

    patch_nghttp3_for_msvc(&nghttp3_dir);

    // Build nghttp3.
    let nghttp3_dst = cmake::Config::new(&nghttp3_dir)
        .define("ENABLE_STATIC_LIB", "ON")
        .define("ENABLE_SHARED_LIB", "OFF")
        .define("ENABLE_LIB_ONLY", "ON")
        .define("BUILD_TESTING", "OFF")
        .build();

    // Library path.
    let lib_dir = if nghttp3_dst.join("lib64").exists() {
        nghttp3_dst.join("lib64")
    } else {
        nghttp3_dst.join("lib")
    };

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=nghttp3");

    // Pass metadata to dependent crates.
    println!("cargo:include={}/include", nghttp3_dst.display());

    #[cfg(feature = "overwrite")]
    overwrite_bindgen(&out_dir);
}

fn patch_nghttp3_for_msvc(nghttp3_dir: &std::path::Path) {
    if !cfg!(target_env = "msvc") {
        return;
    }

    // The vendored nghttp3 branch is built by CMake during tests. Keep this
    // patch local to OUT_DIR so Windows CI can compile without carrying a fork
    // of upstream C sources in the repository.
    let macro_path = nghttp3_dir.join("lib/nghttp3_macro.h");
    let mut contents =
        std::fs::read_to_string(&macro_path).expect("Failed to read nghttp3_macro.h");
    let marker = "HTTP3_RS_MSVC_NGHTTP3_MINMAX_PATCH";

    if contents.contains(marker) {
        return;
    }

    let patch = format!(
        r#"

/* {marker}
 * MSVC treats plain char as compatible with signed char in _Generic
 * associations, so nghttp3's upstream generic min/max macros fail with C7700.
 * The current call sites pass variables or simple expressions, so a portable
 * comparison macro is enough for the Windows build.
 */
#if defined(_MSC_VER)
#  undef nghttp3_max
#  undef nghttp3_min
#  define nghttp3_max(A, B) ((A) < (B) ? (B) : (A))
#  define nghttp3_min(A, B) ((A) < (B) ? (A) : (B))
#endif
"#
    );

    contents = contents.replace(
        "#endif /* !defined(NGHTTP3_MACRO_H) */",
        &format!("{patch}\n#endif /* !defined(NGHTTP3_MACRO_H) */"),
    );

    std::fs::write(macro_path, contents).expect("Failed to patch nghttp3_macro.h");
}

#[cfg(feature = "overwrite")]
fn overwrite_bindgen(out_dir: &PathBuf) {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    // Build include directory where version.h is generated.
    let nghttp3_installed_include = out_dir.join("include");
    // Source include directory where nghttp3.h lives.
    let nghttp3_source_include = out_dir.join("nghttp3/lib/includes");

    bindgen::Builder::default()
        .header(manifest_dir.join("src/wrapper.h").to_str().unwrap())
        .clang_arg(format!("-I{}", nghttp3_installed_include.display()))
        .clang_arg(format!("-I{}", nghttp3_source_include.display()))
        .allowlist_function("nghttp3_.*")
        .allowlist_type("nghttp3_.*")
        .allowlist_var("NGHTTP3_.*")
        .generate()
        .expect("Failed to generate nghttp3 bindings")
        .write_to_file(manifest_dir.join("src/bindings.rs"))
        .expect("Failed to write nghttp3 bindings");
}
