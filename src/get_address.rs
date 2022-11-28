
// SPDX-License-Identifier: MIT
#![allow(dead_code,unused_imports)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use core::slice;

use futures::stream::TryStreamExt;
use rtnetlink::{new_connection, Error, Handle};
use crate::frr_ospf;
use frr_ospf::{*};
extern crate netlink_packet_route; 
use netlink_packet_route::{
    nlas::address::Nla,
    AddressMessage,
    NetlinkMessage,
    RtnlMessage,
    AF_INET,
    AF_INET6,
    NLM_F_ACK,
    NLM_F_CREATE,
    NLM_F_EXCL,
    NLM_F_REPLACE,
    NLM_F_REQUEST,
};
use rtnetlink:: packet::rtnl::link::nlas::Nla as lNla ;

pub async fn dump_addresses(all_intfs:Vec<(String, u32, u32)>,slice: * mut Link, len:u32) -> Result<u32, String> {
    //pub async fn dump_addresses<'a>(all_intfs:Vec<String>,slice: std::sync::Arc<* mut Link<'a>>, len:u32) -> Result<(), String> {
    let intfs:&mut[Link];
    unsafe { intfs = slice::from_raw_parts_mut(slice, len as usize);}
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    let mut used=0;
    for (_, link) in all_intfs.iter().enumerate() {

        let dump_ret = _dump_addresses(link.1, link.2, handle.clone(), link.0.clone(), &mut intfs[used as usize..len as usize]).await;
        if dump_ret.is_err() {
            Err(format!("{:?}",dump_ret.err()))?
        }else {
            used+=dump_ret.unwrap();
        }
    }

    Ok(used as u32)
}

async fn _dump_addresses(_if_idx:u32, mtu:u32, handle: Handle, link: String, intfs:& mut [Link]) -> Result<i32, Error> {
    let len = intfs.len();
    let mut used = 0;
    let mut links = handle.link().get().match_name(link.clone()).execute();
    if let Some(link) = links.try_next().await? {
        let mut addresses = handle
            .address()
            .get()
            .set_link_index_filter(link.header.index)
            .execute();
        let old_used=used;
        while let Some(msg) = addresses.try_next().await?  {
            if msg.header.family == 2 && msg.nlas.len() > 0 {
                if used < len {
                    intfs[used].flags= link.header.flags;
                    intfs[used].prefix_len = msg.header.prefix_len;
                    intfs[used].mtu = mtu;
                    for nl in msg.nlas.iter() {
                        match nl {
                            Nla::Label(l)=> {
                                let mlen=std::cmp::min(l.len(),intfs[used].name.len());
                                #[cfg(target_arch = "x86_64")]
                                let tl= unsafe {&*(l.as_bytes() as *const[u8] as *const[i8])};
                                #[cfg(target_arch = "x86_64")]
                                let _ = &mut intfs[used].name[..mlen].copy_from_slice(tl);
                                #[cfg(any(target_arch = "aarch64",target_arch="powerpc"))]
                                let _ = &mut intfs[used].name[..mlen].copy_from_slice(l.as_bytes());
                            }
                            Nla::Local(ip) => {
                                if ip.len() == 4 {
                                    let ip_str = format!("{}.{}.{}.{}",ip[0],ip[1],ip[2],ip[3]);
                                    //println!("{}",ip_str);
                                    let mlen=std::cmp::min(ip_str.len(),IPV4_LEN);
                                    #[cfg(target_arch = "x86_64")]
                                    let ti= unsafe {&*(ip_str.as_bytes() as *const[u8] as *const[i8])};
                                    #[cfg(target_arch = "x86_64")]
                                    let _ = &mut intfs[used].ip[..mlen].copy_from_slice(ti);
                                    #[cfg(any(target_arch = "aarch64",target_arch="powerpc"))]
                                    let _ = &mut intfs[used].ip[..mlen].copy_from_slice(ip_str.as_bytes());
                                }
                            }
                            _ => {
                            }
                        }
                    }
                    used+=1;
                    //msg.header.address, msg.header.prefix_len, msg.header.flags.
                }
            }
            //println!("{:?}", msg);
        }
        if used == old_used {
            if used < len {
                intfs[used].flags= link.header.flags;
                intfs[used].prefix_len = 0;
                intfs[used].mtu = mtu;
                let mut interface_name="".to_owned();
                for nla in link.nlas.into_iter() {
                    if let lNla::IfName(name) = nla {
                        interface_name=name;
                        break;
                    }
                }
                let mlen=std::cmp::min(interface_name.len(),intfs[used].name.len());
                #[cfg(target_arch = "x86_64")]
                let tl= unsafe {&*(interface_name.as_bytes() as *const[u8] as *const[i8])};
                #[cfg(target_arch = "x86_64")]
                let _ = &mut intfs[used].name[..mlen].copy_from_slice(tl);
                #[cfg(any(target_arch = "aarch64",target_arch="powerpc"))]
                let _ = &mut intfs[used].name[..mlen].copy_from_slice(interface_name.as_bytes());
                let ip_str = format!("{}.{}.{}.{}",0,0,0,0);
                //println!("{}",ip_str);
                let mlen=std::cmp::min(ip_str.len(),IPV4_LEN);
                #[cfg(target_arch = "x86_64")]
                let ti= unsafe {&*(ip_str.as_bytes() as *const[u8] as *const[i8])};
                #[cfg(target_arch = "x86_64")]
                let _ = &mut intfs[used].ip[..mlen].copy_from_slice(ti);
                #[cfg(any(target_arch = "aarch64",target_arch="powerpc"))]
                let _ = &mut intfs[used].ip[..mlen].copy_from_slice(ip_str.as_bytes());

                used+=1;
            }
        }
    } else {
        println!("link {} not found", link);
    }
    Ok(used as i32)
}
