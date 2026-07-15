fn main() {
    // Ship one binary: embed the sing-box engine (+ wintun driver on Windows)
    // when present at build time (CI drops them into bin/). Absent → runtime
    // falls back to a sing-box binary next to the app or on PATH.
    println!("cargo:rustc-check-cfg=cfg(embed_singbox)");
    println!("cargo:rerun-if-changed=bin/sing-box.exe");
    println!("cargo:rerun-if-changed=bin/wintun.dll");
    println!("cargo:rerun-if-changed=bin/sing-box");
    let exists = |p: &str| std::path::Path::new(p).exists();
    let embed = match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("windows") => exists("bin/sing-box.exe") && exists("bin/wintun.dll"),
        Ok("linux") => exists("bin/sing-box"),
        _ => false,
    };
    if embed {
        println!("cargo:rustc-cfg=embed_singbox");
    }
    tauri_build::build()
}
