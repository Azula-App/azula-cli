//! `libazula_host.so`: the attach-mode compute broker (`azula compute serve
//! --local --worker-socket …`) as a JNI library, loaded by the azula Android
//! app's `:vmhost` process (`vm/BROKER.md` §9). Java class
//! `app.azula.vmhost.AzulaHost`, static native methods:
//!
//! ```java
//! static native String  start(String configJson);   // "" on success, else an error message
//! static native void    stop();
//! static native String  mintGrant(String ttl, String label); // `compute grant --json`, or {"error":…}
//! static native String  listGrants();                // JSON array, or {"error":…}
//! static native boolean revoke(String id);
//! ```
//!
//! `configJson`: `{"computeDir","vmName","workerSocket","vmCpus","vmMemoryMb","logFile"}`.
//! The broker runs on its own multi-thread tokio runtime in a background
//! thread; `tracing` output goes to `logFile` (Android has no useful stderr).
//! The grant calls work on `computeDir` too, so they need a prior `start`.

// The broker's attach mode exists only where the local backend does; elsewhere
// (macOS, Windows) this crate is deliberately empty so `cargo build --workspace` still works.
#![cfg(any(target_os = "linux", target_os = "android"))]

use std::fs::OpenOptions;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use azula::compute::grants::{parse_duration, MintOptions, OP_EXEC, OP_VM};
use azula::compute::host;
use azula::compute::local::{validate_serve_flags, AttachOpts};
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Notify;
use tracing::{error, info};

/// How long `start` waits for the endpoint to bind (it waits up to 30 s for a
/// home relay) before reporting failure.
const READY_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    compute_dir: PathBuf,
    #[serde(default = "default_vm_name")]
    vm_name: String,
    worker_socket: PathBuf,
    #[serde(default)]
    vm_cpus: u32,
    #[serde(default)]
    vm_memory_mb: u64,
    #[serde(default)]
    log_file: Option<PathBuf>,
}

fn default_vm_name() -> String {
    "default".to_owned()
}

struct Running {
    shutdown: Arc<Notify>,
    thread: JoinHandle<()>,
}

static STATE: Mutex<Option<Running>> = Mutex::new(None);

/// A small runtime for the grant calls (they are async only to learn the
/// relay when no broker is running).
fn util_rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime"))
}

fn init_logging(file: &std::path::Path) -> Result<()> {
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let f = OpenOptions::new().create(true).append(true).open(file).with_context(|| format!("opening {}", file.display()))?;
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    // A second `start` in the same process finds the subscriber installed already.
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false).with_writer(Mutex::new(f)).try_init();
    Ok(())
}

fn start_impl(config_json: &str) -> Result<()> {
    let cfg: Config = serde_json::from_str(config_json).context("invalid config JSON")?;
    let mut state = STATE.lock().unwrap();
    if state.is_some() {
        return Err(anyhow!("the broker is already running"));
    }
    if let Some(log) = &cfg.log_file {
        init_logging(log)?;
    }
    let attach = AttachOpts { socket: cfg.worker_socket.clone(), cpus: cfg.vm_cpus, memory_mb: cfg.vm_memory_mb };
    validate_serve_flags(true, &cfg.vm_name, "", Some(&attach.socket), Some(attach.cpus), Some(attach.memory_mb)).map_err(|e| anyhow!(e))?;
    std::fs::create_dir_all(&cfg.compute_dir).with_context(|| format!("creating {}", cfg.compute_dir.display()))?;
    // SAFETY-ish: set before the broker thread exists; `compute_dir()` reads it.
    std::env::set_var("AZULA_COMPUTE_DIR", &cfg.compute_dir);

    let shutdown = Arc::new(Notify::new());
    let (tx, rx) = mpsc::channel::<std::result::Result<(), String>>();
    let sd = shutdown.clone();
    let vm_name = cfg.vm_name.clone();
    let thread = std::thread::Builder::new()
        .name("azula-broker".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().thread_name("azula-rt").build() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(Err(format!("tokio runtime: {e}")));
                    return;
                }
            };
            let ready = tx.clone();
            let res = rt.block_on(host::run_attach_broker(
                &vm_name,
                attach,
                move || {
                    let _ = ready.send(Ok(()));
                },
                async move { sd.notified().await },
            ));
            match res {
                Ok(()) => info!("broker stopped"),
                Err(e) => {
                    error!("broker failed: {e:#}");
                    let _ = tx.send(Err(format!("{e:#}")));
                }
            }
            rt.shutdown_timeout(Duration::from_secs(5));
        })
        .context("spawning the broker thread")?;

    match rx.recv_timeout(READY_TIMEOUT) {
        Ok(Ok(())) => {
            *state = Some(Running { shutdown, thread });
            Ok(())
        }
        Ok(Err(e)) => {
            let _ = thread.join();
            Err(anyhow!(e))
        }
        Err(_) => {
            shutdown.notify_one();
            Err(anyhow!("the broker did not become ready within {}s (no home relay?)", READY_TIMEOUT.as_secs()))
        }
    }
}

fn stop_impl() {
    let running = STATE.lock().unwrap().take();
    if let Some(r) = running {
        r.shutdown.notify_one();
        let _ = r.thread.join();
    }
}

fn mint_impl(ttl: &str, label: &str) -> Result<String> {
    let ttl = parse_duration(if ttl.is_empty() { "6h" } else { ttl }).map_err(|e| anyhow!("ttl: {e}"))?;
    let opts = MintOptions { label: label.to_owned(), ttl, ops: vec![OP_EXEC.to_owned(), OP_VM.to_owned()], vms: vec!["*".to_owned()] };
    let (grant, token) = util_rt().block_on(host::grant(&opts))?;
    Ok(json!({"grant": grant.public_json(), "token": token}).to_string())
}

fn list_impl() -> Result<String> {
    let grants = host::list_grants()?;
    Ok(serde_json::Value::Array(grants.iter().map(|g| g.public_json()).collect()).to_string())
}

fn err_json(e: impl std::fmt::Display) -> String {
    json!({"error": e.to_string()}).to_string()
}

/// Run `f`, turning a panic into an error string.
fn guarded<T>(f: impl FnOnce() -> T, on_panic: impl FnOnce(String) -> T) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(p) => {
            let msg = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_else(|| "panic".into());
            error!("panic in JNI call: {msg}");
            on_panic(format!("internal error: {msg}"))
        }
    }
}

fn arg(env: &mut JNIEnv, s: &JString) -> String {
    if s.is_null() {
        return String::new();
    }
    env.get_string(s).map(|s| s.into()).unwrap_or_default()
}

fn ret(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_app_azula_vmhost_AzulaHost_start(mut env: JNIEnv, _: JClass, config: JString) -> jstring {
    let cfg = arg(&mut env, &config);
    let msg = guarded(|| start_impl(&cfg).err().map(|e| format!("{e:#}")).unwrap_or_default(), |m| m);
    ret(&mut env, &msg)
}

#[no_mangle]
pub extern "system" fn Java_app_azula_vmhost_AzulaHost_stop(_: JNIEnv, _: JClass) {
    guarded(stop_impl, |_| ());
}

#[no_mangle]
pub extern "system" fn Java_app_azula_vmhost_AzulaHost_mintGrant(mut env: JNIEnv, _: JClass, ttl: JString, label: JString) -> jstring {
    let (ttl, label) = (arg(&mut env, &ttl), arg(&mut env, &label));
    let out = guarded(|| mint_impl(&ttl, &label).unwrap_or_else(|e| err_json(format!("{e:#}"))), err_json);
    ret(&mut env, &out)
}

#[no_mangle]
pub extern "system" fn Java_app_azula_vmhost_AzulaHost_listGrants(mut env: JNIEnv, _: JClass) -> jstring {
    let out = guarded(|| list_impl().unwrap_or_else(|e| err_json(format!("{e:#}"))), err_json);
    ret(&mut env, &out)
}

#[no_mangle]
pub extern "system" fn Java_app_azula_vmhost_AzulaHost_revoke(mut env: JNIEnv, _: JClass, id: JString) -> jboolean {
    let id = arg(&mut env, &id);
    let ok = guarded(
        || match host::revoke(&id, false) {
            Ok(found) => found,
            Err(e) => {
                error!("revoke {id}: {e:#}");
                false
            }
        },
        |_| false,
    );
    if ok {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parses_camel_case_with_defaults() {
        let c: Config = serde_json::from_str(r#"{"computeDir":"/a","workerSocket":"/b.sock","vmCpus":8,"vmMemoryMb":4096}"#).unwrap();
        assert_eq!(c.vm_name, "default");
        assert_eq!((c.vm_cpus, c.vm_memory_mb), (8, 4096));
        assert!(c.log_file.is_none());
    }

    #[test]
    fn bad_config_is_an_error_not_a_panic() {
        assert!(start_impl("{").is_err());
        assert!(start_impl(r#"{"computeDir":"/a","workerSocket":"relative"}"#).is_err());
    }
}
