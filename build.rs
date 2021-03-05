fn main() {
    cfg_if::cfg_if! {
        if #[cfg(feature = "server")] {
            tonic_build::configure()
            .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
            .compile(
                &["server.proto"],
                &["."],
            )
            .unwrap();
            println!("cargo:rerun-if-changed=server.proto");
        }
    }
}
