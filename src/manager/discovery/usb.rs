use super::read_file;
use crate::manager::model::DeviceMode;
use std::{fs, io, path::Path};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pico2 {
    pub mode: DeviceMode,
    pub serial: Option<String>,
    pub port: String,
}

pub fn list_pico2() -> io::Result<Vec<Pico2>> {
    list_pico2_in(Path::new("/sys/bus/usb/devices"))
}
pub fn list_pico2_in(root: &Path) -> io::Result<Vec<Pico2>> {
    let mut boards = Vec::new();
    for (i, entry) in fs::read_dir(root)?.enumerate() {
        if i >= 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "USB entry limit exceeded",
            ));
        }
        let entry = entry?;
        let path = entry.path();
        let text = |name| {
            read_file(&path.join(name), 64)
                .ok()
                .and_then(|v| String::from_utf8(v).ok())
                .map(|v| v.trim().to_owned())
        };
        let mode = match (text("idVendor").as_deref(), text("idProduct").as_deref()) {
            (Some("1209"), Some("4b45")) => DeviceMode::Application,
            (Some("2e8a"), Some("000f")) => DeviceMode::Bootloader,
            _ => continue,
        };
        let serial =
            text("serial").filter(|s| s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit()));
        boards.push(Pico2 {
            mode,
            serial,
            port: entry.file_name().to_string_lossy().into_owned(),
        });
    }
    boards.sort_by(|a, b| a.port.cmp(&b.port));
    Ok(boards)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_apps_bootloader_and_bad_serial() {
        let root = std::env::temp_dir().join(format!("p2-usb-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        assert!(list_pico2_in(&root).unwrap().is_empty());
        for (name, vendor, product, serial) in [
            ("1", "1209", "4b45", "0123456789abcdef"),
            ("2", "1209", "4b45", "bad"),
            ("3", "2e8a", "000f", ""),
        ] {
            let p = root.join(name);
            fs::create_dir(&p).unwrap();
            fs::write(p.join("idVendor"), vendor).unwrap();
            fs::write(p.join("idProduct"), product).unwrap();
            fs::write(p.join("serial"), serial).unwrap();
            let boards = list_pico2_in(&root).unwrap();
            assert_eq!(boards.len(), name.parse::<usize>().unwrap());
            if name != "3" {
                assert!(boards.iter().all(|b| b.mode == DeviceMode::Application));
            }
        }
        let boards = list_pico2_in(&root).unwrap();
        assert_eq!(boards.len(), 3);
        assert!(boards[0].serial.is_some());
        assert!(boards[1].serial.is_none());
        assert_eq!(boards[2].mode, DeviceMode::Bootloader);
        fs::remove_dir_all(root.join("1")).unwrap();
        fs::remove_dir_all(root.join("2")).unwrap();
        let bootsel = list_pico2_in(&root).unwrap();
        assert_eq!(bootsel.len(), 1);
        assert_eq!(bootsel[0].mode, DeviceMode::Bootloader);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn rejects_more_than_entry_cap() {
        let root = std::env::temp_dir().join(format!("p2-usb-cap-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        for i in 0..1025 {
            fs::write(root.join(i.to_string()), "").unwrap();
        }
        assert!(list_pico2_in(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
