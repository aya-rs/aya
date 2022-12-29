//! Network interfaces representing kernel network interfaces.

use std::ffi::CStr;

use libc::if_nameindex;

#[derive(Debug, Clone)]
/// A kernel network interface.
// if_name isn't stored because it can change in the kernel and aya won't know
pub struct NetworkInterface {
    pub(crate) index: i32,
}

impl NetworkInterface {
    /// Provides a number that can be used to identify this interface on this system.
    pub fn index(&self) -> i32 {
        self.index
    }

    /// Extracts the interface name from the kernel.
    pub fn name(&self) -> Result<String, std::io::Error> {
        let mut buffer: [libc::c_char; libc::IF_NAMESIZE] = [0; libc::IF_NAMESIZE];
        let name = unsafe {
            // Returns null on error
            let res = libc::if_indextoname(self.index as u32, buffer.as_mut_ptr());

            if res.is_null() {
                return Err(std::io::Error::last_os_error());
            }

            CStr::from_ptr(buffer.as_ptr())
        };

        Ok(name.to_string_lossy().to_string())
    }

    /// Provides a [Vec] of all operating system network interfaces, including virtual ones.
    /// # Example
    ///
    /// ```
    /// let interfaces_names: Vec<String> = NetworkInterface::list()
    ///     .iter()
    ///     .map(|interface| interface.name().unwrap())
    ///     .collect();
    /// ```
    pub fn list() -> Vec<NetworkInterface> {
        let mut list = Vec::new();

        // The nameindex array is terminated by an interface with if_index == 0 and if_name == null
        let head = unsafe { libc::if_nameindex() };
        let mut curr = head;

        while let Ok(interface) = NetworkInterface::try_from(unsafe { *curr }) {
            list.push(interface);
            curr = unsafe { curr.add(1) };
        }

        unsafe {
            libc::if_freenameindex(head);
        };

        list
    }
}

impl TryFrom<if_nameindex> for NetworkInterface {
    type Error = ();

    // Returns Err is the interface is invalid (zeroed)
    fn try_from(value: if_nameindex) -> Result<Self, ()> {
        if value.if_index == 0 || value.if_name.is_null() {
            return Err(());
        }

        Ok(NetworkInterface {
            index: value.if_index as i32,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use crate::interface::NetworkInterface;

    #[test]
    fn network_interface_list() {
        let interfaces_dir = "/sys/class/net";

        let expected: Vec<String> = std::fs::read_dir(interfaces_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();

        let interfaces = NetworkInterface::list();

        assert_eq!(expected.len(), interfaces.len());

        for interface in interfaces {
            let name = interface.name().unwrap().to_string();
            assert!(expected.contains(&name));
        }
    }

    #[test]
    fn network_interface_try_from() {
        use libc::if_nameindex;
        use std::ptr::null_mut;

        let name = CString::new("eth0").unwrap();

        let k_interface = if_nameindex {
            if_index: 1,
            if_name: name.as_ptr() as *mut i8,
        };

        let interface = NetworkInterface::try_from(k_interface).unwrap();

        assert_eq!(interface.index(), 1);

        let invalid_k_interface = if_nameindex {
            if_index: 0,
            if_name: null_mut(),
        };

        let res = NetworkInterface::try_from(invalid_k_interface);
        assert_eq!(res.unwrap_err(), ());

        let invalid_k_interface = if_nameindex {
            if_index: 1,
            if_name: null_mut(),
        };

        let res = NetworkInterface::try_from(invalid_k_interface);
        assert_eq!(res.unwrap_err(), ());
    }

    #[test]
    fn network_interface_name() {
        let interfaces_dir = "/sys/class/net";

        let first_interface_path = std::fs::read_dir(interfaces_dir)
            .expect("Failed to read sysfs interface directory")
            .next();

        if let Some(first_interface_path) = first_interface_path {
            let (name, index) = {
                let entry = first_interface_path.unwrap();
                let file_name = entry.file_name();
                let mut path = entry.path();
                path.push("ifindex");
                let index_contents = String::from_utf8(std::fs::read(path).unwrap()).unwrap();
                let index = index_contents.trim().parse::<i32>().unwrap();
                (file_name, index)
            };

            let interface = NetworkInterface { index };

            assert_eq!(
                name.to_string_lossy().to_string(),
                interface.name().unwrap()
            );
        } else {
            panic!("no interfaces found in {interfaces_dir} to test");
        }
    }
}
