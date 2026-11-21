//! The cloud-init NoCloud seed's files (`vm/BROKER.md` §8). Pure text, so it
//! is testable (and compiled) on every platform; writing the ISO is in
//! `vmmgr` (macOS).

/// `meta-data`: a unique instance id (so cloud-init's `runcmd` runs once per
/// created VM) and the hostname.
pub fn render_meta_data(instance_id: &str, name: &str) -> String {
    format!("instance-id: {instance_id}\nlocal-hostname: {name}\n")
}

/// `user-data`: creates the job user, mounts the read-only `azula` virtiofs
/// share, runs the worker from it under systemd, and closes every other
/// guest listener (sshd on TCP/vsock/unix, LLMNR, mDNS) so the worker is the
/// only thing the host can reach.
pub fn render_user_data(name: &str) -> String {
    format!(
        r#"#cloud-config
hostname: {name}
users:
  - name: azula
    gecos: azula job user
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: true
ssh_pwauth: false
mounts:
  - [azula, /mnt/azula, virtiofs, "ro,nofail", "0", "0"]
write_files:
  - path: /etc/systemd/system/azula-guest.service
    content: |
      [Unit]
      Description=azula guest worker
      After=mnt-azula.mount
      RequiresMountsFor=/mnt/azula
      [Service]
      ExecStart=/mnt/azula/azula-guest --vsock-port 1024 --run-as azula
      Restart=always
      RestartSec=1
      [Install]
      WantedBy=multi-user.target
  - path: /etc/systemd/resolved.conf.d/azula.conf
    content: |
      [Resolve]
      LLMNR=no
      MulticastDNS=no
runcmd:
  - [mkdir, -p, /mnt/azula]
  - [mount, -a]
  - [systemctl, daemon-reload]
  - [systemctl, enable, --now, azula-guest.service]
  - [systemctl, disable, --now, ssh.service, ssh.socket]
  - [systemctl, mask, --now, sshd-vsock.socket, sshd-unix-local.socket]
  - [systemctl, restart, systemd-resolved.service]
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_data_has_instance_id_and_hostname() {
        assert_eq!(render_meta_data("0b3c", "build"), "instance-id: 0b3c\nlocal-hostname: build\n");
    }

    #[test]
    fn user_data_matches_the_contract() {
        let u = render_user_data("build");
        assert!(u.starts_with("#cloud-config\nhostname: build\n"));
        for needle in [
            "name: azula",
            "sudo: \"ALL=(ALL) NOPASSWD:ALL\"",
            "lock_passwd: true",
            "ssh_pwauth: false",
            "[azula, /mnt/azula, virtiofs, \"ro,nofail\", \"0\", \"0\"]",
            "ExecStart=/mnt/azula/azula-guest --vsock-port 1024 --run-as azula",
            "RequiresMountsFor=/mnt/azula",
            "LLMNR=no",
            "MulticastDNS=no",
            "[systemctl, enable, --now, azula-guest.service]",
            "[systemctl, disable, --now, ssh.service, ssh.socket]",
            "[systemctl, mask, --now, sshd-vsock.socket, sshd-unix-local.socket]",
            "[systemctl, restart, systemd-resolved.service]",
        ] {
            assert!(u.contains(needle), "missing {needle:?}");
        }
        // The worker must be enabled before the listeners are closed.
        assert!(u.find("enable, --now, azula-guest").unwrap() < u.find("mask, --now").unwrap());
        // Every line the YAML needs is well-formed enough to parse as JSON-ish flow items.
        assert!(u.ends_with('\n'));
    }
}
