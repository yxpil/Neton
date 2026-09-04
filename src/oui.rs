//! Embedded OUI (MAC vendor) lookup for common home-network vendors.
//!
//! The table is intentionally small and best-effort: it covers vendors that
//! are frequent in home LANs (routers, phones, IoT, virtual machines). Unknown
//! prefixes return `None` — callers must render that as `null`, never guess.

/// Look up the vendor of a MAC address like `A4:2B:8C:11:22:33`,
/// `a4-2b-8c-112233` or `a42b8c112233`. Returns the vendor name when the
/// first three octets are known.
pub fn vendor_for_mac(mac: &str) -> Option<&'static str> {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() < 6 {
        return None;
    }
    let prefix = &hex[..6];
    OUI_TABLE
        .iter()
        .find(|(oui, _)| *oui == prefix)
        .map(|(_, vendor)| *vendor)
}

/// Well-known OUI prefixes (lowercase, no separators) of common home-network
/// device vendors. Best-effort and intentionally conservative.
const OUI_TABLE: &[(&str, &str)] = &[
    // Apple
    ("000393", "Apple"),
    ("f01898", "Apple"),
    ("a483e7", "Apple"),
    ("acbc32", "Apple"),
    ("dc2b61", "Apple"),
    // Samsung
    ("001632", "Samsung"),
    ("8c7712", "Samsung"),
    // Huawei
    ("001882", "Huawei"),
    ("346bd3", "Huawei"),
    // Xiaomi
    ("286c07", "Xiaomi"),
    ("640980", "Xiaomi"),
    ("8cbebe", "Xiaomi"),
    // TP-Link
    ("50c7bf", "TP-Link"),
    ("a42b8c", "TP-Link"),
    ("c025e9", "TP-Link"),
    // Espressif (ESP8266 / ESP32 IoT modules)
    ("240ac4", "Espressif"),
    ("5ccf7f", "Espressif"),
    ("30aea4", "Espressif"),
    ("84f3eb", "Espressif"),
    ("246f28", "Espressif"),
    // Raspberry Pi
    ("b827eb", "Raspberry Pi"),
    ("dca632", "Raspberry Pi"),
    ("e45f01", "Raspberry Pi"),
    // Google / Amazon smart home
    ("f4f5e8", "Google"),
    ("44650d", "Amazon"),
    // Routers / NAS
    ("00095b", "NETGEAR"),
    ("001b2f", "NETGEAR"),
    ("00055d", "D-Link"),
    ("000d88", "D-Link"),
    ("000c6e", "ASUSTek"),
    ("001bfc", "ASUSTek"),
    ("001217", "Cisco-Linksys"),
    ("001132", "Synology"),
    ("245a4c", "QNAP"),
    // Cameras
    ("4447cc", "Hikvision"),
    ("3cef8c", "Dahua"),
    // Telecom / chips
    ("0019c5", "ZTE"),
    ("001b21", "Intel"),
    ("a088b4", "Intel"),
    ("00e04c", "Realtek"),
    ("001018", "Broadcom"),
    // PCs / phones / consoles
    ("00155d", "Microsoft"),
    ("0013a9", "Sony"),
    ("c8d719", "LG Innotek"),
    // Virtual machines
    ("005056", "VMware"),
    ("000c29", "VMware"),
    ("525400", "QEMU/KVM"),
    ("080027", "VirtualBox"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_common_formats() {
        assert_eq!(vendor_for_mac("A4:2B:8C:11:22:33"), Some("TP-Link"));
        assert_eq!(vendor_for_mac("a4-2b-8c-11-22-33"), Some("TP-Link"));
        assert_eq!(vendor_for_mac("a42b8c112233"), Some("TP-Link"));
        assert_eq!(vendor_for_mac("b827eb:aa:bb:cc"), Some("Raspberry Pi"));
    }

    #[test]
    fn unknown_or_malformed_mac_is_none() {
        assert_eq!(vendor_for_mac("00:11:22:33:44:55"), None);
        assert_eq!(vendor_for_mac(""), None);
        assert_eq!(vendor_for_mac("a4"), None);
        assert_eq!(vendor_for_mac("zz:zz:zz:zz:zz:zz"), None);
    }

    #[test]
    fn espressif_prefixes_are_iot() {
        assert_eq!(vendor_for_mac("5C:CF:7F:00:00:01"), Some("Espressif"));
        assert_eq!(vendor_for_mac("24:6F:28:00:00:01"), Some("Espressif"));
    }
}
