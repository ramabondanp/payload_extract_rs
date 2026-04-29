#[allow(
    dead_code,
    clippy::doc_overindented_list_items,
    clippy::enum_variant_names
)]
pub mod chromeos_update_engine {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}

#[allow(
    dead_code,
    clippy::doc_overindented_list_items,
    clippy::enum_variant_names,
    clippy::module_inception
)]
pub mod ota_metadata {
    include!(concat!(env!("OUT_DIR"), "/build.tools.releasetools.rs"));
}

pub use chromeos_update_engine::*;
