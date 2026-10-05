use std::{
    fs::{self, OpenOptions},
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use crate::HidDeviceDescriptor;

pub const UHID_PATH: &str = "/dev/uhid";

pub struct HidrawNode {
    pub path: PathBuf,
    pub mode: u32,
}

pub fn check_uhid_access() -> io::Result<()> {
    let _file = OpenOptions::new().read(true).write(true).open(UHID_PATH)?;
    Ok(())
}

/// The hidraw nodes of HID devices with `descriptor`'s vendor and product
/// IDs.
pub fn hidraw_nodes_for_descriptor(
    descriptor: &HidDeviceDescriptor,
) -> io::Result<Vec<HidrawNode>> {
    hidraw_nodes_under(
        Path::new("/sys/class/hidraw"),
        Path::new("/dev"),
        descriptor.vendor_id,
        descriptor.product_id,
    )
}

/// Log a warning for each of `nodes` every user may open.
///
/// The shipped udev rule makes the node mode 0600 with an ACL for the user of
/// the active session; without it the mode is up to the system, and a node
/// every user can open lets any local user ask the key to sign.
pub fn warn_if_world_accessible(nodes: &[HidrawNode]) {
    for node in nodes {
        let mode = node.mode & 0o777;
        if mode & 0o007 != 0 {
            log::warn!(
                "{} is world-accessible (mode {mode:o}): every local user can use the key. Install the \
                 udev rules (pqkey setup) or tighten its permissions",
                node.path.display()
            );
        }
    }
}

/// [`hidraw_nodes_for_descriptor`] with sysfs's `class/hidraw` at `sys_hidraw`
/// and the device nodes in `dev`.
fn hidraw_nodes_under(
    sys_hidraw: &Path,
    dev: &Path,
    vendor_id: u32,
    product_id: u32,
) -> io::Result<Vec<HidrawNode>> {
    let mut nodes = Vec::new();
    let entries = match fs::read_dir(sys_hidraw) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(nodes),
        Err(err) => return Err(err),
    };

    for entry in entries.flatten() {
        let sys_path = entry.path();
        let uevent_path = sys_path.join("device").join("uevent");
        let uevent = match fs::read_to_string(&uevent_path) {
            Ok(contents) => contents,
            Err(_) => continue,
        };
        if !matches_descriptor(&uevent, vendor_id, product_id) {
            continue;
        }
        let dev_name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };
        let dev_path = dev.join(dev_name);
        let metadata = match fs::metadata(&dev_path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let mode = metadata.permissions().mode();
        nodes.push(HidrawNode {
            path: dev_path,
            mode,
        });
    }

    Ok(nodes)
}

fn matches_descriptor(uevent: &str, vendor_id: u32, product_id: u32) -> bool {
    for line in uevent.lines() {
        if let Some(value) = line.strip_prefix("HID_ID=") {
            let mut parts = value.split(':');
            let _bus = parts.next();
            let vendor = parts.next();
            let product = parts.next();
            if let (Some(vendor), Some(product)) = (vendor, product)
                && let (Ok(vendor), Ok(product)) = (
                    u32::from_str_radix(vendor, 16),
                    u32::from_str_radix(product, 16),
                )
                && vendor == vendor_id
                && product == product_id
            {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TempDir, logs};
    use log::Level;

    /// The shipped rule for the key's hidraw node, its continuation lines
    /// joined.
    fn hidraw_rule() -> String {
        include_str!("../../../../../contrib/udev/70-pqkey.rules")
            .replace("\\\n", "")
            .lines()
            .find(|line| line.starts_with(r#"SUBSYSTEM=="hidraw""#))
            .expect("a hidraw rule")
            .to_owned()
    }

    /// Snap browsers (Ubuntu's Firefox and Chromium) only open devices udev
    /// tags for them, which snapd does by USB IDs a uhid device lacks.
    #[test]
    fn the_udev_rules_let_snap_browsers_open_the_key() {
        let rule = hidraw_rule();
        for tag in ["uaccess", "snap_firefox_firefox", "snap_chromium_chromium"] {
            assert!(rule.contains(&format!(r#"TAG+="{tag}""#)), "{tag}: {rule}");
        }
        assert!(rule.contains(r#"MODE="0600""#), "{rule}");
        // udev reads rules files in the order of their names: snapd acts on
        // its tags in 70-snap.*.rules, systemd on uaccess in
        // 73-seat-late.rules.
        for later in [
            "70-snap.firefox.rules",
            "70-snap.chromium.rules",
            "73-seat-late.rules",
        ] {
            assert!("70-pqkey.rules" < later, "{later}");
        }
    }

    /// A fake sysfs `class/hidraw` and `/dev` with one node per
    /// `(name, HID_ID, mode)`.
    fn fake_nodes(dir: &TempDir, nodes: &[(&str, &str, u32)]) -> (PathBuf, PathBuf) {
        let (sys, dev) = (dir.path().join("sys"), dir.path().join("dev"));
        fs::create_dir_all(&dev).unwrap();
        for (name, hid_id, mode) in nodes {
            let device = sys.join(name).join("device");
            fs::create_dir_all(&device).unwrap();
            fs::write(
                device.join("uevent"),
                format!("DRIVER=hid-generic\nHID_ID={hid_id}\n"),
            )
            .unwrap();
            let node = dev.join(name);
            fs::write(&node, b"").unwrap();
            fs::set_permissions(&node, fs::Permissions::from_mode(*mode)).unwrap();
        }
        (sys, dev)
    }

    #[test]
    fn nodes_are_found_by_vendor_and_product_and_world_access_is_reported() {
        let dir = TempDir::new("hidraw-nodes");
        let (sys, dev) = fake_nodes(
            &dir,
            &[
                ("hidraw3", "0003:00001209:00000001", 0o600),
                ("hidraw5", "0003:00001209:00000001", 0o666),
                ("hidraw7", "0003:00001050:00000407", 0o666),
            ],
        );
        let mut nodes = hidraw_nodes_under(&sys, &dev, 0x1209, 0x0001).unwrap();
        nodes.sort_by(|a, b| a.path.cmp(&b.path));
        let names: Vec<_> = nodes
            .iter()
            .map(|node| node.path.file_name().unwrap())
            .collect();
        assert_eq!(names, ["hidraw3", "hidraw5"]);

        logs::install();
        warn_if_world_accessible(&nodes);
        let warned = logs::containing("is world-accessible");
        assert!(
            warned.iter().any(|(level, message)| *level == Level::Warn
                && message.contains("hidraw5 is world-accessible (mode 666)")),
            "{warned:?}"
        );
        assert!(
            !warned
                .iter()
                .any(|(_, message)| message.contains("hidraw3")),
            "{warned:?}"
        );
    }

    #[test]
    fn a_missing_sysfs_class_is_no_nodes() {
        let dir = TempDir::new("hidraw-none");
        assert!(
            hidraw_nodes_under(&dir.path().join("absent"), dir.path(), 1, 1)
                .unwrap()
                .is_empty()
        );
    }
}
