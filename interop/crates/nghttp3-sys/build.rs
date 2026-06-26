use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let nghttp3_dir = prepare_submodule_source("nghttp3", &manifest_dir, &out_dir);

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

    generate_bindings(
        &nghttp3_dst.join("include"),
        &nghttp3_dir.join("lib/includes"),
        &out_dir.join("bindings.rs"),
    );
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
        fs::remove_dir_all(&build_dir).expect("Failed to remove old nghttp3 build source");
    }
    copy_dir_all(&submodule_dir, &build_dir).expect("Failed to copy nghttp3 submodule");
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
    // The crates.io package carries the lib-only CMake inputs, not nghttp3's
    // test submodules. Keep this check focused on files the build actually
    // needs, so published builds do not try to run git.
    submodule_dir.join("CMakeLists.txt").exists()
        && required_paths_ready(
            submodule_dir,
            &["lib/sfparse/sfparse.c", "lib/sfparse/sfparse.h"],
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

fn generate_bindings(
    installed_include: &std::path::Path,
    source_include: &std::path::Path,
    output: &std::path::Path,
) {
    let target = std::env::var("TARGET").expect("TARGET not set by Cargo");

    // Bindings are generated for the Cargo target, not the build host. This
    // matters for 32-bit CI where bindgen layout tests would otherwise use
    // x86_64 sizes.
    bindgen::Builder::default()
        .header(
            installed_include
                .join("nghttp3/nghttp3.h")
                .to_str()
                .unwrap(),
        )
        .clang_arg(format!("--target={target}"))
        .clang_arg(format!("-I{}", installed_include.display()))
        .clang_arg(format!("-I{}", source_include.display()))
        .allowlist_function("nghttp3_.*")
        .allowlist_type("nghttp3_.*")
        .allowlist_var("NGHTTP3_.*")
        .generate()
        .expect("Failed to generate nghttp3 bindings")
        .write_to_file(output)
        .expect("Failed to write nghttp3 bindings");
}
