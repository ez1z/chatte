fn main() {
    // Ship one .exe: embed the sing-box engine + wintun driver when they're
    // present at build time (CI drops them into bin/). Absent → runtime falls
    // back to a sing-box.exe next to the app or on PATH.
    println!("cargo:rustc-check-cfg=cfg(embed_singbox)");
    println!("cargo:rerun-if-changed=bin/sing-box.exe");
    println!("cargo:rerun-if-changed=bin/wintun.dll");
    if std::path::Path::new("bin/sing-box.exe").exists()
        && std::path::Path::new("bin/wintun.dll").exists()
    {
        println!("cargo:rustc-cfg=embed_singbox");
    }
    tauri_build::build()
}
