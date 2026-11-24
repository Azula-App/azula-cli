//! `libazula_host.so`: the native half of the azula Android app's on-phone VM host, loaded by its
//! `:vmhost` process. Two JNI surfaces: `broker` runs the compute broker, `xz` decodes the guest
//! image.

// The broker's attach mode exists only where the local backend does; elsewhere (macOS, Windows)
// this crate is without it so `cargo build --workspace` still works.
#[cfg(any(target_os = "linux", target_os = "android"))]
mod broker;

// Any unix, so its tests run on a Mac.
#[cfg(unix)]
mod xz;
