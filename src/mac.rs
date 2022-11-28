#![allow(dead_code,unused_imports)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use ethtool::*;

use std::convert::TryInto;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Read;
use std::num::ParseIntError;
use std::str::FromStr;
use std::fmt::Error;

use libc::sockaddr;

use netdevice::{get_hardware, set_hardware};

use libc::c_int;

use std::io::Error as ioError;
use std::io::Result as ioResult;
use std::process::ExitCode;
use std::ffi::CStr;

/// Returns a new UDP socket
fn get_socket() -> ioResult<c_int> {
    use libc::{AF_INET, IPPROTO_UDP, SOCK_DGRAM};
    let res = unsafe { libc::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) };

    match res {
        -1 => Err(ioError::last_os_error()),
        sock => Ok(sock),
    }
}

fn close_socket( fd:i32 ) {
    unsafe {libc::close(fd)};
}

fn get_mac(sock: c_int, ifname: &str) -> ioResult<MAC> {
    let addr = get_hardware(sock, ifname)?;
    Ok(addr.into())
}

fn set_mac(sock: c_int, ifname: &str, addr: &MAC) -> ioResult<()> {
    let mut old_addr = get_hardware(sock, ifname)?;

    old_addr.sa_data = addr.clone().into();
    set_hardware(sock, ifname, old_addr)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MAC {
    data: [u8; 6],
}

impl MAC {
    pub fn new() -> Self {
        Self { data: [0u8; 6] }
    }

    pub fn new_random(bia: bool) -> Self {
        use std::fs::File;

        let mut out = ["/dev/urandom", "/dev/hwrng", "/dev/random"]
            .iter()
            .filter_map(|rng| File::open(rng).ok())
            .find_map(|mut f| {
                let mut out = Self::new();
                f.read_exact(&mut out.data).ok().map(|_| out)
            })
        .expect("No working random number generator!");

        // make sure it's not multicast and not locally-administered
        out.data[0] &= 0xfc;
        if !bia {
            // set locally-administered bit
            out.data[0] |= 0x02;
        }

        out
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        let mut out = Self::new();
        out.data.copy_from_slice(slice);
        out
    }

    pub fn get_ending(&self) -> &[u8; 3] {
        self.data[3..].try_into().unwrap()
    }

    pub fn set_ending(&mut self, ending: &[u8; 3]) {
        self.data[3..].copy_from_slice(ending);
    }
}

impl From<sockaddr> for MAC {
    fn from(addr: sockaddr) -> Self {
        let mut out = Self::new();

        for (n, x) in addr.sa_data[0..6].iter().enumerate() {
            out.data[n] = *x as u8;
        }

        out
    }
}

impl Into<[i8; 14]> for MAC {
    fn into(self) -> [i8; 14] {
        let mut out = [0i8; 14];

        for (n, b) in self.data.iter().enumerate() {
            out[n] = *b as i8;
        }

        out
    }
}

impl Into<[u8; 14]> for MAC {
    fn into(self) -> [u8; 14] {
        let mut out = [0u8; 14];

        for (n, b) in self.data.iter().enumerate() {
            out[n] = *b as u8;
        }

        out
    }
}

impl Display for MAC {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.data[0], self.data[1], self.data[2], self.data[3], self.data[4], self.data[5]
            )
    }
}


#[derive(Debug)]
pub enum ParseMACError {
    ParseIntError(ParseIntError),
    FormatError,
}


impl Display for ParseMACError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            ParseMACError::ParseIntError(e) => write!(f, "Failed to parse integer for MAC: {}", e),
            ParseMACError::FormatError => write!(f, "MAC has invalid format"),
        }
    }
}


impl FromStr for MAC {
    type Err = ParseMACError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = Self::new();

        for (n, p) in s.split(':').enumerate() {
            if n >= out.data.len() {
                return Err(ParseMACError::FormatError);
            }

            out.data[n] = u8::from_str_radix(p, 16).map_err(|e| ParseMACError::ParseIntError(e))?;
        }

        Ok(out)
    }
}

#[test] fn basic_test1() {
    let n = CStr::from_bytes_with_nul(b"enp0s3.100\0").unwrap();
    let m = CStr::from_bytes_with_nul(b"00:20:60:00:00:8e\0").unwrap();
    let r = SetMac(n.as_ptr(),m.as_ptr());
    assert_eq!(r,0);
    }
#[test] fn basic_test2() {
    let n = CStr::from_bytes_with_nul(b"enp0s3.101\0").unwrap();
    let m = CStr::from_bytes_with_nul(b"00:20:60:00:00:8e\0").unwrap();
    let r = SetMac(n.as_ptr(),m.as_ptr());
    assert_eq!(r,-3);
}
#[test] fn basic_test3() {
    let n = CStr::from_bytes_with_nul(b"enp0s3.100\0").unwrap();
    let m = CStr::from_bytes_with_nul(b"00:20:60:00:00:8e:99\0").unwrap();
    let r = SetMac(n.as_ptr(),m.as_ptr());
    assert_eq!(r,-1);
}

#[no_mangle]
/// mac is XX:XX:XX:XX:XX:XX
/// name is interface name, example, eth0
/// return = -1 parameter error, 
/// return = -2 socket error, 
/// return = -3 set hw address error, 
/// return == 0; means success
pub extern "C" fn SetMac(name:*const libc::c_char,mac:*const libc::c_char)->i32 {
    let ifname;
    let a_mac;
    unsafe {
        if let Ok(s) = CStr::from_ptr(mac).to_str() {
            if s.parse::<MAC>().is_err() {
                return -1
            }
            a_mac= s.parse::<MAC>().unwrap();
        } else {
            return -1;
        }
        if let Ok(s) = CStr::from_ptr(name).to_str() {
            ifname= s;
        } else {
            return -1;
        }
    }

    if let Ok(sock) = get_socket() {
        if let Ok(_) = set_mac(sock, &ifname, &a_mac) {
            close_socket(sock);
            0
        } else {
            return -3;
        }
    }else {
        return  -2
    }
}
