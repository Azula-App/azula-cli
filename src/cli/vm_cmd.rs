//! `azula vm` — create, list and delete VMs on the host (Apple silicon macOS
//! only), and start/stop/inspect them through the broker from anywhere.

use anyhow::Result;
use clap::{Args, Subcommand};

use super::compute_cmd::{close_quietly, die, open_session, require_token, TokenArg};
use crate::compute::client;

#[derive(Debug, Args)]
pub(super) struct VmArgs {
    #[command(subcommand)]
    action: VmAction,
}

#[derive(Debug, Subcommand)]
enum VmAction {
    /// Host (Apple silicon macOS): create a VM from a checksum-verified base
    /// image (downloaded on first use). The image is cloned, never modified.
    Create {
        /// VM name: lowercase letters, digits and `-`.
        #[arg(value_name = "NAME")]
        name: String,
        /// Base image.
        #[arg(long, default_value = "debian-13", value_name = "IMAGE")]
        image: String,
        /// Virtual CPUs.
        #[arg(long, default_value_t = 4, value_name = "N")]
        cpus: u32,
        /// Memory in MiB.
        #[arg(long, default_value_t = 4096, value_name = "MIB")]
        memory: u64,
        /// Disk size in GiB (sparse; grown from the image's size).
        #[arg(long, default_value_t = 32, value_name = "GIB")]
        disk_gb: u64,
        /// `nat` gives the VM outbound networking; `none` gives it no network
        /// device at all.
        #[arg(long, default_value = "nat", value_name = "MODE", value_parser = ["nat", "none"])]
        network: String,
    },
    /// Host (Apple silicon macOS): list the VMs on this host.
    List {
        /// Machine-readable output: a JSON array.
        #[arg(long)]
        json: bool,
    },
    /// Host (Apple silicon macOS): delete a VM's files. Refuses while the VM
    /// is running.
    Delete {
        #[arg(value_name = "NAME")]
        name: String,
    },
    /// Client: start a VM through the broker and wait until its worker is
    /// ready. Needs a grant that allows `vm`.
    Start(RemoteVmArgs),
    /// Client: stop a VM through the broker (graceful shutdown). Needs a
    /// grant that allows `vm`. Refuses with `vm_busy` while jobs are running
    /// unless `--force`.
    Stop(RemoteVmArgs),
    /// Client: show a VM's state and whether its worker answers.
    Status(RemoteVmArgs),
}

#[derive(Debug, Args)]
struct RemoteVmArgs {
    #[command(flatten)]
    token: TokenArg,
    /// The VM. Default: the grant's only VM when it names exactly one,
    /// otherwise `default`.
    #[arg(value_name = "NAME")]
    name: Option<String>,
    /// Stop even if jobs are running (they end as `interrupted`).
    #[arg(long)]
    force: bool,
    /// Machine-readable output: a JSON array of VM status objects.
    #[arg(long)]
    json: bool,
}

pub(super) async fn run(args: VmArgs) -> Result<()> {
    match args.action {
        VmAction::Create { name, image, cpus, memory, disk_gb, network } => host::create(&name, &image, cpus, memory, disk_gb, &network).await,
        VmAction::List { json } => host::list(json),
        VmAction::Delete { name } => host::delete(&name),
        VmAction::Start(a) => remote("start", a).await,
        VmAction::Stop(a) => remote("stop", a).await,
        VmAction::Status(a) => remote("status", a).await,
    }
}

async fn remote(op: &str, a: RemoteVmArgs) -> Result<()> {
    let token = require_token(&a.token);
    let (ep, session) = match open_session(&token).await {
        Ok(x) => x,
        Err(f) => die(f.exit_code(), &f.message()),
    };
    let result = client::vm_op(session, op, a.name.as_deref(), a.force).await;
    close_quietly(ep).await;
    let vms = match result {
        Ok(v) => v,
        Err(f) => die(f.exit_code(), &f.message()),
    };
    if a.json {
        println!("{}", serde_json::Value::Array(vms));
        return Ok(());
    }
    for v in &vms {
        println!(
            "{}  {}  worker {}  ({} cpu, {} MiB, {} GiB, {}, network {}){}{}",
            v["name"].as_str().unwrap_or("?"),
            v["state"].as_str().unwrap_or("?"),
            v["worker"].as_str().unwrap_or("?"),
            v["cpus"],
            v["memory_mb"],
            v["disk_gb"],
            v["image"].as_str().unwrap_or("?"),
            v["network"].as_str().unwrap_or("nat"),
            v["jobs_running"].as_u64().map(|n| format!("  {n} job(s) running")).unwrap_or_default(),
            v["error"].as_str().map(|e| format!("\n  last start failed: {}", e.lines().next().unwrap_or(""))).unwrap_or_default(),
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
mod host {
    use super::*;
    use crate::compute::vmmgr::{create_vm, delete_vm, list_offline, CreateOptions, Paths};

    pub(super) async fn create(name: &str, image: &str, cpus: u32, memory_mb: u64, disk_gb: u64, network: &str) -> Result<()> {
        let paths = Paths::new(crate::compute::vm_dir());
        let dir = create_vm(&paths, name, &CreateOptions { image: image.to_owned(), cpus, memory_mb, disk_gb, network: network.to_owned() }).await?;
        println!("created VM `{name}` in {}", dir.display());
        println!("start it with `azula compute serve` plus `azula vm start {name}`, or by running a command with `azula compute exec`");
        Ok(())
    }

    pub(super) fn list(json: bool) -> Result<()> {
        let vms = list_offline(&Paths::new(crate::compute::vm_dir()));
        if json {
            println!("{}", serde_json::to_string(&vms)?);
            return Ok(());
        }
        if vms.is_empty() {
            println!("no VMs (create one with `azula vm create NAME`)");
        }
        for v in vms {
            println!("{:<20} {:<8} {} cpu, {} MiB, {} GiB, {}", v.name, v.state, v.cpus, v.memory_mb, v.disk_gb, v.image);
        }
        Ok(())
    }

    pub(super) fn delete(name: &str) -> Result<()> {
        delete_vm(&Paths::new(crate::compute::vm_dir()), name)?;
        println!("deleted VM `{name}`");
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
mod host {
    use super::*;

    pub(super) async fn create(_: &str, _: &str, _: u32, _: u64, _: u64, _: &str) -> Result<()> {
        die(2, crate::compute::HOST_ONLY_MSG)
    }
    pub(super) fn list(_: bool) -> Result<()> {
        die(2, crate::compute::HOST_ONLY_MSG)
    }
    pub(super) fn delete(_: &str) -> Result<()> {
        die(2, crate::compute::HOST_ONLY_MSG)
    }
}
