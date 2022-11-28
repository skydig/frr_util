#![allow(dead_code,unused_imports)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use core::slice;
use std::time::Duration;
use std::fmt::Debug;
use tokio::runtime::Runtime;
use tokio::task;
use libc::{c_char,memcpy,c_void};
use std::ffi::{CString,CStr};

use crate::Telnet;
use std::any::Any;
use ipaddress::IPAddress;
use ipnetwork::IpNetwork;
use crate::{get_links,flush_addresses,add_address, set_link, get_address, add_route};
use rtnetlink::{
    new_connection,
    packet::rtnl::{
        constants::{AF_BRIDGE, RTEXT_FILTER_BRVLAN},
        link::nlas::Nla,
    },
    Error,
    Handle,
};
use subprocess::{Exec,Redirection};
pub const IPV4_LEN:usize = 19;
pub const IFNAMESIZE:usize = 16;
fn result_str_is_ok(input:&String)->bool {
    //println!("result str={} len={} bytes={:?}", input, input.len(), input.as_bytes());
    if input.len() == 0 || (input.len() == 1 && input.chars().nth(input.len()-1)==Some(10 as char)) || input == "No more data." || input.contains("clear ip ospf process"){
        true
    } else {
        false
    }

}

//#[tokio::main]
async fn frr_ospf<T:Any+Debug>(stru:&mut T) -> Result<String, Box<dyn std::error::Error>> {
    let mut telnet = Telnet::builder()
        .prompt("ospfd> ")
        .login_prompt("_", "Password: ")
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1:2604")
        .await?;

    telnet.login("_", "zebra").await?;

    telnet.prompt("ospfd# ");
    telnet.execute("enable").await?;

    let value_any = stru as &mut dyn Any;
    match value_any.downcast_mut::<OspfIntf>(){
        Some(intf)=>{
            // ......
            /*
               if intf.area < 0 || intf.area > 4294967295  {
               Err("error number is wrong")?
               }
               */
            let intf_cstr = unsafe {CStr::from_ptr(intf.name)};
            let intf_str = intf_cstr.to_str().unwrap();

            if intf.config == 1 {
                let intf_ip_cstr = unsafe{CStr::from_ptr(intf.ipmask)};
                //   let intf_ip_str = std::str::from_utf8(&intf.ipmask).unwrap();
                let intf_ip_str = intf_ip_cstr.to_str().unwrap();
                let ipnet:Result<IpNetwork,_>=intf_ip_str.to_string().parse::<IpNetwork>();
                if ipnet.is_ok() == false {
                    Err(format!("ip address {} is invalid",intf_ip_str))?
                }
                let intf_ip = IPAddress::parse(intf_ip_str);

                if intf_ip.is_ok() {

                }else {
                    Err(format!("ip address {} is invalid", intf_ip_str))?
                }
                let (connection, handle, _) = new_connection().unwrap();
                tokio::spawn(connection);
                if let Err(_e) = get_links::get_link_by_name(handle.clone(), intf_str.to_string()).await {
                    Err(format!("{}", _e))?
                }
                if let Err(_e) = flush_addresses::flush_addresses_func(&intf_str.to_string()).await {
                    Err(_e.to_string())?
                }
                if let Err(_e) = add_address::add_address_func(intf_str, ipnet.unwrap()).await {
                    Err(_e.to_string())?
                }
                if let Err(_e) = set_link::set_link_up_down_func(intf_str, false).await {
                    Err(_e.to_string())?
                }
                telnet.prompt("ospfd(config)# ");
                telnet.execute("conf term").await?;
                telnet.prompt("ospfd(config-if)# ");
                let mut res = telnet.execute(&format!("interface {}",intf_str)).await?;
                if !result_str_is_ok(&res) {
                    Err(res)?
                }
                telnet.execute(&format!("no ip ospf area")).await.unwrap();
                res = telnet.execute(&format!("ip ospf area {}", intf.area)).await?;
                if !result_str_is_ok(&res) {
                    Err(res)?
                }
            } else {
                telnet.prompt("ospfd(config)# ");
                telnet.execute("conf term").await?;
                telnet.prompt("ospfd(config-if)# ");
                let (connection, handle, _) = new_connection().unwrap();
                tokio::spawn(connection);
                if let Err(_e) = get_links::get_link_by_name(handle.clone(), intf_str.to_string()).await {
                    Err(format!("{}", _e))?
                }
                let mut res = telnet.execute(&format!("interface {}",intf_str)).await?;
                if !result_str_is_ok(&res) {
                    Err(res)?
                }
                res = telnet.execute(&format!("no ip ospf area")).await?;
                if !result_str_is_ok(&res) {
                    Err(res)?
                }
            }
        }
        None=>{
        }
    }
    match value_any.downcast_mut::<OspfLoopback>(){
        Some(lo)=>{
            let lo_ip_cstr = unsafe{CStr::from_ptr(lo.lo)};
            //   let intf_ip_str = std::str::from_utf8(&intf.ipmask).unwrap();
            let lo_ip_str = lo_ip_cstr.to_str().unwrap();
            let lo_name = format!("lo:{}",0u16);
            let ipnet:Result<IpNetwork,_>=lo_ip_str.to_string().parse::<IpNetwork>();
            if ipnet.is_ok() == false {
                Err(format!("loopback ip address {} is invalid",lo_ip_str))?
            }

            use std::process::Command;
            use std::io::{self, Write};

            Command::new("ifconfig").arg(&lo_name).arg("0").output().expect("failed to execute ifconfig process");
            let output = Command::new("ifconfig").arg(&lo_name).arg(lo_ip_str).arg("netmask").arg("255.255.255.255").output()
                .expect("failed to execute ifconfig process");
            //io::stdout().write_all(&output.stdout).unwrap();

            if output.stderr.len()>0 {
                io::stderr().write_all(&output.stderr).unwrap();
                Err("ifconfig lo:0 error")?
            }

            telnet.prompt("ospfd(config)# ");
            telnet.execute("conf term").await?;
            telnet.prompt("ospfd(config-if)# "); 
            let mut res = telnet.execute(&format!("interface lo")).await?;
            if !result_str_is_ok(&res) {
                Err(res)?
            }
            telnet.execute(&format!("no ip ospf area")).await.unwrap();//no-exist will report error. so unwrap 
            res = telnet.execute(&format!("ip ospf area {}", lo.area)).await?;
            if !result_str_is_ok(&res) {
                Err(res)?
            }
            telnet.execute(&format!("clear ip ospf process")).await?;
        }
        None=>{
        }
    }
    match value_any.downcast_mut::<OspfRouterId>(){
        Some(rid)=>{
            let rid_cstr = unsafe{CStr::from_ptr(rid.router_id)};
            //   let intf_ip_str = std::str::from_utf8(&intf.ipmask).unwrap();
            let rid_str = rid_cstr.to_str().unwrap();
            telnet.prompt("ospfd(config)# ");
            telnet.execute("conf term").await?;
            telnet.prompt("ospfd(config-router)# ");
            telnet.execute("router ospf").await?;
            let res = telnet.execute(&format!("ospf router-id {}", rid_str)).await?;
            if !result_str_is_ok(&res) {
                Err(res)?
            }
            telnet.execute(&format!("clear ip ospf process")).await?;
        }
        None=>{
        }
    }
    match value_any.downcast_mut::<Redist>(){
        Some(red)=>{
            match red.0  {
                RedistRouteType::Default=> {
                    telnet.prompt("ospfd(config)# ");
                    telnet.execute("conf term").await?;
                    telnet.prompt("ospfd(config-router)# ");
                    telnet.execute("router ospf").await?;
                    let mut res="yes or no distribute?".to_owned();
                    if red.3 == 1 {
                        if red.1 == -1 && red.2 == -1 { 
                            res = telnet.execute("default-information originate always").await?;
                        } else if red.1 == -1 && red.2 != -1 {
                            res = telnet.execute(&format!("default-information originate metric-type {}",red.2)).await?;
                        } else if red.2 == -1 && red.1 != -1 {
                            res = telnet.execute(&format!("default-information originate metric {}",red.1)).await?;
                        } else if red.2 != -1 && red.1 != -1 {
                            let res1 = telnet.execute(&format!("default-information originate metric {}",red.1)).await?;
                            if !result_str_is_ok(&res1) {
                                Err(res1)?
                            }
                            res = telnet.execute(&format!("default-information originate metric-type {}",red.2)).await?;
                        }
                    }else if red.3 == 0{
                        res = telnet.execute(&format!("no default-information originate")).await?;
                    } else {
                        Err(res.clone())?
                    }
                    if !result_str_is_ok(&res) {
                        Err(res)?
                    }
                }
                RedistRouteType::Static => {
                    telnet.prompt("ospfd(config)# ");
                    telnet.execute("conf term").await?;
                    telnet.prompt("ospfd(config-router)# ");
                    telnet.execute("router ospf").await?;
                    let mut res="yes or no distribute?".to_owned();
                    if red.3 == 1 {
                        if red.1 == -1 && red.2 == -1 { 
                            res = telnet.execute("redistribute static").await?;
                        } else if red.1 == -1 && red.2 != -1 {
                            res = telnet.execute(&format!("redistribute static metric-type {}",red.2)).await?;
                        } else if red.2 == -1 && red.1 != -1{
                            res = telnet.execute(&format!("redistribute static metric {}",red.1)).await?;
                        } else if red.2 != -1 && red.1 != -1 {
                            let res1 = telnet.execute(&format!("redistribute static metric-type {}",red.2)).await?;
                            if !result_str_is_ok(&res1) {
                                Err(res1)?
                            }
                            res = telnet.execute(&format!("redistribute static metric {}",red.1)).await?;
                        }
                    }else if red.3 == 0{
                        res = telnet.execute(&format!("no redistribute static")).await?;
                    } else {
                        Err(res.clone())?
                    }
                    if !result_str_is_ok(&res) {
                        Err(res)?
                    }
                }
                RedistRouteType::Kernel=> {
                    telnet.prompt("ospfd(config)# ");
                    telnet.execute("conf term").await?;
                    telnet.prompt("ospfd(config-router)# ");
                    telnet.execute("router ospf").await?;
                    let mut res="yes or no distribute?".to_owned();
                    if red.3 == 1 {
                        if red.1 == -1 && red.2 == -1 { 
                            res = telnet.execute("redistribute kernel").await?;
                        } else if red.1 == -1 && red.2 != -1 {
                            res = telnet.execute(&format!("redistribute kernel metric-type {}",red.2)).await?;
                        } else if red.2 == -1 && red.1 != -1 {
                            res = telnet.execute(&format!("redistribute kernel metric {}",red.1)).await?;
                        } else if red.1 != -1 && red.2 != -1 {
                            let res1 = telnet.execute(&format!("redistribute kernel metric-type {}",red.2)).await?;
                            if !result_str_is_ok(&res1) {
                                Err(res1)?
                            }
                            res = telnet.execute(&format!("redistribute kernel metric {}",red.1)).await?;
                        }
                    }else if red.3 == 0{
                        res = telnet.execute(&format!("no redistribute kernel")).await?;
                    } else {
                        Err(res.clone())?
                    }
                    if !result_str_is_ok(&res) {
                        Err(res)?
                    }
                }
                RedistRouteType::Connected=> {
                    telnet.prompt("ospfd(config)# ");
                    telnet.execute("conf term").await?;
                    telnet.prompt("ospfd(config-router)# ");
                    telnet.execute("router ospf").await?;
                    let mut res="yes or no distribute?".to_owned();
                    if red.3 == 1 {
                        if red.1 == -1 && red.2 == -1 { 
                            res = telnet.execute("redistribute connected").await?;
                        } else if red.1 == -1 && red.2 != -1 {
                            res = telnet.execute(&format!("redistribute connected metric-type {}",red.2)).await?;
                        } else if red.2 == -1 && red.1 != -1 {
                            res = telnet.execute(&format!("redistribute connected metric {}",red.1)).await?;
                        } else if red.1 != -1 && red.2 != -1 {
                            let res1 = telnet.execute(&format!("redistribute connected metric-type {}",red.2)).await?;
                            if !result_str_is_ok(&res1) {
                                Err(res1)?
                            }
                            res = telnet.execute(&format!("redistribute connected metric {}",red.1)).await?;
                        }
                    }else if red.3 == 0{
                        res = telnet.execute(&format!("no redistribute connected")).await?;
                    } else {
                        Err(res.clone())?
                    }
                    if !result_str_is_ok(&res) {
                        Err(res)?
                    }
                }
            }
        }
        None=>{
        }
    }
    match value_any.downcast_mut::<OspfRoutes>(){
        Some(rt)=>{
            let res = telnet.execute("show ip ospf route json").await?;
            rt.0=res;
        }
        None=>{
        }
    }
    match value_any.downcast_mut::<Neighbor>(){
        Some(nb)=>{
            let res = telnet.execute("show ip ospf nei json").await?;
            nb.0=res;
        }
        None=>{
        }
    }
    match value_any.downcast_mut::<OspfInterfaces>(){
        Some(oi)=>{
            let res = telnet.execute("show ip ospf int json").await?;
            oi.0=res;
        }
        None=>{
        }
    }
    match value_any.downcast_mut::<OspfInfo>(){
        Some(oi)=>{
            let res = telnet.execute("show ip ospf json").await?;
            oi.0=res;
        }
        None=>{
        }
    }
    Ok("".to_owned())
}

#[derive(Debug)]
#[repr(C)]
/// area[0-4294967295]
/// name is interface name
/// ipmask is interface ip with mask, example 192.168.3.22/24
/// config is 1, install this interface, config is 0, uninstall this interface 
/// error_msg is buf allocated by caller
/// error_msg_len is buf length 
pub struct OspfIntf{
    pub area: u32,
    pub name:*const c_char, //[c_char;INTF_NAME_LEN],
    pub ipmask:*const c_char,
    pub config:i32,
    pub error_msg:*mut c_char,
    pub error_msg_len:u16,
}

#[derive(Debug)]
#[repr(C)]
/// gateway is ip of gateway, example 192.168.3.1
/// dest_ipmask is ip network/host address with mask, example 192.168.3.0/24, 192.168.3.4/32
/// intf_name is interface name
/// rt_type is gateway or interface, 1:gateway, 0:interface
/// config is 1, install static route, config is 0, uninstall static route
/// error_msg is buf allocaed by caller
/// error_msg_len is buf length 
pub struct OspfStaticRoute{
    pub gateway:*const c_char,
    pub dest_ipmask:*const c_char,
    pub intf_name:*const c_char,
    pub rt_type:u8, 
    pub config:i32,
    pub error_msg:*mut  c_char,
    pub error_msg_len:u16,
}

#[derive(Debug)]
#[repr(C)]
/// idx is 0 to 65535 reserved, not used
/// area[0-4294967295]
/// lo is loopback, example 192.192.192.192
/// error_msg is buf allocaed by caller
/// error_msg_len is buf length 
pub struct OspfLoopback{
    pub idx:u16,
    pub area:u32,
    pub lo:*const c_char,
    //    pub config:i32,
    pub error_msg:*mut  c_char,
    pub error_msg_len:u16,
}

#[derive(Debug)]
#[repr(C)]
/// router_id is router's id, example 1.1.1.1
/// error_msg is buf allocaed by caller
/// error_msg_len is buf length 
pub struct OspfRouterId{
    pub router_id:*const c_char,
    pub error_msg:*mut  c_char,
    pub error_msg_len:u16,
}

#[derive(Debug)]
pub struct OspfInfo(pub String);
#[derive(Debug)]
pub struct IpRoutes(pub String);
#[derive(Debug)]
pub struct OspfRoutes(pub String);
#[derive(Debug)]
pub struct Interfaces(pub Vec<String>);
#[derive(Debug)]
pub struct OspfInterfaces(pub String);
#[derive(Debug)]
pub struct Neighbor(pub String);

#[repr(u8)]
#[derive(Debug)]
pub enum RedistRouteType {
    Kernel=1,
    Connected,
    Static,
    Default,
}

#[derive(Debug)]
pub struct Redist(RedistRouteType,i32,i8, i8);

#[no_mangle]
/// install/uninstall static route
/// return < 0; error_msg should be checked
/// return == 0; means success
pub extern "C" fn ConfOspfLoopback(
    a: *mut OspfLoopback,
    ) -> i32{ 
    let ret;
    let runtime = Runtime::new().unwrap();
    unsafe {
        let res = runtime.block_on(frr_ospf(&mut *a));
        let mut retc=-1;
        ret = match res {
            Ok(result_str) => {retc=0;result_str},
            Err(err)=>format!("{}", err.to_string()),
        };
        let tl = ret.len();
        let t=CString::new(ret).unwrap();
        let mlen=std::cmp::min(tl,(*a).error_msg_len as usize);
        memcpy(CStr::from_ptr((*a).error_msg).as_ptr() as *mut c_void, t.as_ptr() as *const c_void, mlen as usize);
        return retc;
    }
}

#[no_mangle]
/// install/uninstall static route
/// return < 0; error_msg should be checked
/// return == 0; means success
pub extern "C" fn ConfOspfRouterId(
    a: *mut OspfRouterId,
    ) -> i32{ 
    let ret;
    let runtime = Runtime::new().unwrap();
    //        let res = futures::executor::block_on(frr_zebra(&mut *a));
    unsafe {
        let res = runtime.block_on(frr_ospf(&mut *a));
        let mut retc=-1;
        ret = match res {
            Ok(result_str) => {retc=0;result_str},
            Err(err)=>format!("{}", err.to_string()),
        };
        let tl = ret.len();
        let t=CString::new(ret).unwrap();
        let mlen=std::cmp::min(tl,(*a).error_msg_len as usize);
        memcpy(CStr::from_ptr((*a).error_msg).as_ptr() as *mut c_void,t.as_ptr() as *const c_void,mlen as usize);
        return retc;
    }
}

#[no_mangle]
/// install/uninstall static route
/// return < 0; error_msg should be checked
/// return == 0; means success
pub extern "C" fn ConfOspfStaticRt(
    a: *mut OspfStaticRoute,
    ) -> i32{ 
    let runtime = Runtime::new().unwrap();
    unsafe {
        let res = runtime.block_on(frr_static(&mut *a));
        let mut retc=-1;
        let ret = match res {
            Ok(result_str) => {retc=0;result_str},
            Err(err)=>format!("{}", err.to_string()),
        };
        let tl = ret.len();
        let t=CString::new(ret).unwrap();
        let mlen=std::cmp::min(tl,(*a).error_msg_len as usize);
        memcpy(CStr::from_ptr((*a).error_msg).as_ptr() as *mut c_void,t.as_ptr() as *const c_void,mlen as usize);
        return retc;
    }
}

#[no_mangle]
/// redistribute route 
/// metric is (0-16777214)
/// metric type is (1-2)
/// return ==-1 metic error;  ==-2 metric type error; ==-3 other error
/// return == 0; means success
/// metric = -1 means ignore metric
/// metric_type = -1 means ignore metric_type
/// yes_or_no: redistribute(1) or not(0）, if yes_or_no == 0, metirc metric_type parameters all be
/// ignored
pub extern "C" fn RedistRoute(
    rrt:RedistRouteType,
    metric:i32,
    metric_type:i8,
    yes_or_no:i8
    ) -> i32 { 
    if yes_or_no == 1 {
        if (metric > 16777214 || metric < 0) && metric != -1 {
            return -1
        }
        if metric_type != 1 && metric_type != 2 && metric_type != -1 {
            return -2
        }
    }
    let runtime = Runtime::new().unwrap();
    //let res = futures::executor::block_on(frr_ospf(&mut *a));
    let mut stru = Redist(rrt,metric,metric_type, yes_or_no);
    let res = runtime.block_on(frr_ospf(&mut stru));
    let mut retc=-3;
    match res {
        Ok(result_str) => {retc=0;result_str},
        Err(err)=>{println!("{}",err.to_string());format!("{}", err.to_string())},
    };
    return retc;
}

#[derive(Debug)]
#[repr(C)]
/// name is interface name
/// flags come from if.h 
/// IFF_UP                          = 1<<0,  
/// IFF_BROADCAST                   = 1<<1,
/// IFF_DEBUG                       = 1<<2, 
/// IFF_LOOPBACK                    = 1<<3, 
/// IFF_POINTOPOINT                 = 1<<4,
/// IFF_NOTRAILERS                  = 1<<5,
/// IFF_RUNNING                     = 1<<6,
/// IFF_NOARP                       = 1<<7,
/// IFF_PROMISC                     = 1<<8,  
/// IFF_ALLMULTI                    = 1<<9,  
/// IFF_MASTER                      = 1<<10, 
/// IFF_SLAVE                       = 1<<11, 
/// IFF_MULTICAST                   = 1<<12, 
/// IFF_PORTSEL                     = 1<<13, 
/// IFF_AUTOMEDIA                   = 1<<14, 
/// IFF_DYNAMIC                     = 1<<15,
/// IFF_LOWER_UP                    = 1<<16,
/// IFF_DORMANT                     = 1<<17, 
/// IFF_ECHO                        = 1<<18, 
///
/// ip is like 192.168.3.2
/// prefix_len is [0..32]
pub struct Link{
    pub name:[libc::c_char;IFNAMESIZE], //[c_char;INTF_NAME_LEN],
    pub ip:[libc::c_char;IPV4_LEN],
    pub flags:u32,
    pub prefix_len:u8,
    pub mtu:u32,
}

#[test] fn basic_test() {    
    let mut lo = [0i8;IFNAMESIZE];
    lo[0]=b'l' as i8;
    lo[1]=b'o' as i8;
    let mut link = Link {
        name:lo,
        ip:[0;IPV4_LEN],
        flags:0,
        prefix_len:0,
        mtu:0,
    };
    DumpLinks(&mut link,1);

    assert!(true);    
}

#[no_mangle]
/// get all OS interfaces 
/// size is length of Link array
/// return < 0; failed 
/// return >= 0; means success, how many Link are fetched
pub extern "C" fn DumpLinks( links:*mut Link, size:u32)->i32 {
    let runtime = Runtime::new().unwrap();
    match runtime.block_on(get_links::dump_links_func()){
        Ok(ret)=>{
            match runtime.block_on(get_address::dump_addresses(ret, links,size)) {
                Ok(used)=> {
                    return used as i32;
                }
                Err(_)=> {
                    return -1;
                }
            }
        }
        Err(_)=>{ return -1;},
    }
}

#[no_mangle]
/// get one network interfaces flags and ip etc 
/// Link's name shoud be set as input parameter
/// size is length of Link array
/// return < 0; failed 
/// return == 0; means success
pub extern "C" fn GetOneLink( one_link:*mut Link, size:u32)->i32 {
    let runtime = Runtime::new().unwrap();
    match runtime.block_on(get_links::dump_links_func()){
        Ok(ret)=>{
            for i in ret.iter() { 
                let mut link_name:Vec<u8>=Vec::new();
                unsafe {
                    for c in (*one_link).name.to_vec().iter() {
                        #[cfg(target_arch = "x86_64")]
                        if c != &0i8 {
                            link_name.push(*c as u8);
                        }
                        #[cfg(any(target_arch = "aarch64",target_arch="powerpc"))]
                        if c != &0u8 {
                            link_name.push(*c as u8);
                        }
                    }
                }
                if i.0 == String::from_utf8(link_name).unwrap(){
                    let mut t_vec:Vec<(String,u32,u32)>=Vec::new();
                    t_vec.push(i.clone());
                    match runtime.block_on(get_address::dump_addresses(t_vec,one_link,size)) {
                        Ok(_)=> {
                            return 0;
                        }
                        Err(e)=> {
                            println!("{:?}",e);
                            return -1;
                        }
                    }
                }
            }
        }
        Err(e)=>{ 
            println!("{:?}",e);
            return -1;}
    }
    -1
}

#[test] fn get_one_test() {    
    let mut lo = [0i8;IFNAMESIZE];
    for (dest,src) in lo.iter_mut().zip(b"enp0s3.100".iter()) {
        *dest = *src as i8;
    }
    let mut link = Link {
        name:lo,
        ip:[0;IPV4_LEN],
        flags:0,
        prefix_len:0,
        mtu:0,
    };
    let ret = GetOneLink(&mut link,1);

    assert!(ret==0);
}
#[test] fn confip_test() {    
    let mut lo = [0i8;IFNAMESIZE];
    lo[0]=b'l' as i8;
    lo[1]=b'o' as i8;
    let ret = ConfLinkIp(lo.as_ptr(),"127.0.1.1/24".to_owned().as_ptr() as* const i8);

    assert!(ret==0);    
    let ret = ConfLinkIp(lo.as_ptr(),"327.0.1.1/24".to_owned().as_ptr() as* const i8);
    assert!(ret==-2);
    let ret = ConfLinkIp(lo.as_ptr(),"127.0.0.1/32".to_owned().as_ptr() as* const i8);
    assert!(ret==0);
}

#[no_mangle]
/// conf network interface ip
/// name is interface name
/// ip is ,for example, 192.168.3.1/23
/// return < 0; failed 
/// return = -2 ;ip format error 
/// return == 0; means success
pub extern "C" fn ConfLinkIp(name:* const libc::c_char, ip:* const libc::c_char  )->i32 {

    let ipnet:Result<IpNetwork,_>;
    unsafe {
        ipnet= CStr::from_ptr(ip).to_str().unwrap().parse::<IpNetwork>();
        if ipnet.is_ok() == false {
            return  -2;
        }
    }
    let sifname = unsafe {CStr::from_ptr(name).to_str().unwrap()};
    let runtime = Runtime::new().unwrap();
    let _res = runtime.block_on(flush_addresses::flush_addresses_func(&sifname.to_string()));
    let res = runtime.block_on(add_address::add_address_func(sifname,ipnet.unwrap()));
    match res {
        Ok(_) => {return 0 ;}
        Err(err)=>{format!("{}", err.to_string()); return -1;}
    };
}

#[test] fn status_test() {    
    let mut lo = [0i8;IFNAMESIZE];
    lo[0]=b'l' as i8;
    lo[1]=b'o' as i8;
    let ret = ConfLinkAdminStatus(lo.as_ptr(),1);
    assert!(ret==0);    

    let ret = ConfLinkAdminStatus(lo.as_ptr(),0);
    assert!(ret==0);    
}

#[test] fn promisc_test() {    
    let mut lo = [0i8;IFNAMESIZE];
    for (dest,src) in lo.iter_mut().zip(b"enp0s3.100".iter()) {
        *dest = *src as i8;
    }
    let ret = ConfLinkPromisc(lo.as_ptr() as *const i8, 1); 
    assert!(ret==0);    
}

#[no_mangle]
/// add/del kernel route
/// gateway is next hop gatway ip
/// dest_ip is destination ip (network or host, example:network 3.3.3.3/21 or host 3.3.3.3 which is
/// equal to 3.3.3.3/32);for default route,dest_ip should be 0.0.0.0/0
/// config=1, add; config=0,delete
/// return < 0; failed
/// return == 0; means success
/// error_msg is buf allocated by caller
/// error_msg_len is buf length
pub extern "C" fn ConfKernelRoute(gateway:* const libc::c_char, dest_ip:*const libc::c_char, config:i8, error_msg:*mut c_char, error_msg_len:u16  ) ->i32 {
    let gw= unsafe {CStr::from_ptr(gateway).to_str().unwrap()};
    let destip= unsafe {CStr::from_ptr(dest_ip).to_str().unwrap()};
    let runtime = Runtime::new().unwrap();
    let res;
    if config == 1 {
        res = runtime.block_on(add_route::add_route_func(&gw.to_string(),&destip.to_string()));
    } else {
        res = runtime.block_on(add_route::del_route_func(&gw.to_string(),&destip.to_string()));
    }
    let mut retc=-1;
    let ret = match res {
        Ok(_) => {retc=0;"".to_owned()},
        Err(err)=>format!("{}", err.to_string()),
    };
    let t=CString::new(ret.clone()).unwrap();
    let mlen=std::cmp::min(ret.len(),error_msg_len as usize);
    unsafe {
        memcpy(error_msg as *mut c_void,t.as_ptr() as *const c_void,mlen as usize);
    }
    return retc;
}

#[no_mangle]
/// conf network interface promiscuous mode 
/// name is interface name
/// is_promisc, 1 promiscuous, 0 no-promiscuous
/// return < 0; failed 
/// return == 0; means success
pub extern "C" fn ConfLinkPromisc(name:* const libc::c_char, is_promisc:i32  ) ->i32 {
    let sifname = unsafe {CStr::from_ptr(name).to_str().unwrap()};
    let runtime = Runtime::new().unwrap();
    let res = runtime.block_on(set_link::set_link_promisc_func(sifname,is_promisc));
    match res {
        Ok(_) => {return 0 ;}
        Err(err)=>{format!("{}", err.to_string()); return -1;}
    };
}

#[no_mangle]
/// conf network interface status(up/down) 
/// up_down, 0 up, 1 down 
/// return < 0;  failed 
/// return == 0; means success
pub extern "C" fn ConfLinkAdminStatus( name:*const libc::c_char, up_down:i32) ->i32{
    let sifname = unsafe {CStr::from_ptr(name).to_str().unwrap()};
    let runtime = Runtime::new().unwrap();
    let updown;
    if up_down == 1 {
        updown = true;
    } else if up_down == 0 {
        updown = false;
    } else {
        return -1;
    }
    let res = runtime.block_on(set_link::set_link_up_down_func(sifname,updown));
    match res {
        Ok(_) => {return 0 ;}
        Err(err)=>{format!("{}", err.to_string()); return -1;}
    };
}

#[test] fn mtu_test() {    
    let mut lo = [0i8;IFNAMESIZE];
    lo[0]=b'l' as i8;
    lo[1]=b'o' as i8;
    let ret = ConfLinkMtu(lo.as_ptr(),60000);

    assert!(ret==0);    
}
#[no_mangle]
/// conf network interface mtu
/// mtu is minimum transfer unit 
/// return < 0; failed 
/// return == 0; means success
pub extern "C" fn ConfLinkMtu( name:*const libc::c_char, mtu:u16) ->i32{
    let sifname = unsafe {CStr::from_ptr(name).to_str().unwrap()};
    let runtime = Runtime::new().unwrap();
    let res = runtime.block_on(set_link::set_link_mtu_func(sifname,mtu as u32));
    match res {
        Ok(_) => {return 0 ;}
        Err(err)=>{format!("{}", err.to_string()); return -1;}
    };
}

#[no_mangle]
/// add/remove interface to ospf
/// return < 0; error_msg should be checked
/// return == 0; means success
pub extern "C" fn ConfOspfInterface(
    a: *mut OspfIntf,
    ) -> i32 { 
    let ret;
    let runtime = Runtime::new().unwrap();
    //let res = futures::executor::block_on(frr_ospf(&mut *a));
    unsafe {
        let res = runtime.block_on(frr_ospf(&mut *a));
        let mut retc=-1;
        ret = match res {
            Ok(result_str) => {retc=0;result_str},
            Err(err)=>format!("{}", err.to_string()),
        };
        let t=CString::new(ret).unwrap();
        memcpy(CStr::from_ptr((*a).error_msg).as_ptr() as *mut c_void,t.as_ptr() as *const c_void,(*a).error_msg_len as usize);
        return retc;
    }
}

pub  fn dump_os_ifs() -> Vec<(String,u32,u32)>{ 
    let runtime = Runtime::new().unwrap();
    match runtime.block_on(get_links::dump_links_func()){
        Ok(ret)=>ret,
        Err(_)=>Vec::new(),
    }
}



#[repr(u8)]
#[derive(Debug)]
pub enum DumpMsgType{
    IPROUTE=1,
    OSPFROUTE,
    OSPFINTF,
    OSPFINFO,
    OSPFNEI,
}

fn vec_i8_into_u8(v:Vec<i8>) -> Vec<u8> {
    let mut v = std::mem::ManuallyDrop::new(v);
    let p = v.as_mut_ptr();
    let len = v.len();
    let cap = v.capacity();
    unsafe { Vec::from_raw_parts(p as *mut u8, len, cap) }
}

#[test] fn msg_len_test() {    
    let v1 = get_dump_len(DumpMsgType::IPROUTE);
    let v2 = get_dump_len(DumpMsgType::OSPFROUTE);
    let v3 = get_dump_len(DumpMsgType::OSPFINTF);
    let v4 = get_dump_len(DumpMsgType::OSPFINFO);
    let v5 = get_dump_len(DumpMsgType::OSPFNEI);
    println!("{} {} {} {} {}",v1,v2,v3,v4,v5);
    let v1buf = vec![0i8;v1 as usize];
    dump_ip_routes( v1buf.as_ptr() as *mut i8, v1 as usize);
    println!("{}",String::from_utf8(vec_i8_into_u8(v1buf)).unwrap());
    let v2buf = vec![0i8;v2 as usize];
    dump_ospf_routes( v2buf.as_ptr() as *mut i8, v2 as usize);
    println!("{}",String::from_utf8(vec_i8_into_u8(v2buf)).unwrap());
    let v3buf = vec![0i8;v3 as usize];
    dump_ospf_intf(v3buf.as_ptr() as *mut i8, v3 as usize);
    println!("{}",String::from_utf8(vec_i8_into_u8(v3buf)).unwrap());
    let v4buf = vec![0i8;v4 as usize];
    dump_ospf_info( v4buf.as_ptr() as *mut i8, v4 as usize);
    println!("{}",String::from_utf8(vec_i8_into_u8(v4buf)).unwrap());
    let v5buf = vec![0i8;v5 as usize];
    dump_ospf_nei( v5buf.as_ptr() as *mut i8, v5 as usize);
    println!("{}",String::from_utf8(vec_i8_into_u8(v5buf)).unwrap());
}

#[no_mangle]
/// before calling of dump..., call this function to get message length
pub  extern "C" fn get_dump_len(t:DumpMsgType)->u32 {
    match t {
        DumpMsgType::IPROUTE =>  {
            let rts="".to_owned();
            let mut ipr=IpRoutes(rts);
            if show_ip_routes(&mut ipr)==0 {
                return ipr.0.len() as u32;
            } else {
                return 0;
            }
        }
        DumpMsgType::OSPFROUTE=>  {
            let rts="".to_owned();
            let mut ipr=OspfRoutes(rts);
            if show_ospf_routes(&mut ipr)==0 {
                return ipr.0.len() as u32;
            } else {
                return 0;
            }
        }
        DumpMsgType::OSPFINTF => {
            let intfs ="".to_owned();
            let mut intf=OspfInterfaces(intfs);
            if show_ospf_int(&mut intf) == 0 {
                return intf.0.len() as u32;
            } else {
                return 0;
            }
        }
        DumpMsgType::OSPFINFO=> {
            let infs ="".to_owned();
            let mut inf=OspfInfo(infs);
            if show_ospf_info(&mut inf) == 0 {
                return inf.0.len() as u32;
            } else {
                return 0;
            }
        }
        DumpMsgType::OSPFNEI=> {
            let ns ="".to_owned();
            let mut n=Neighbor(ns);
            if show_ospf_nei(&mut n) == 0 {
                return n.0.len() as u32;
            } else {
                return 0;
            }
        }
    }
}

#[no_mangle]
/// dump ip route as json message 
pub  extern "C" fn dump_ip_routes( iproute:*mut c_char, len:usize) {
    let rts="".to_owned();
    let mut ipr=IpRoutes(rts);
    if show_ip_routes(&mut ipr)==0 {
        unsafe {
            let cstr = slice::from_raw_parts_mut(iproute, len);
            #[cfg(target_arch = "x86_64")]
            let t_ipr = &*(ipr.0.as_bytes() as *const[u8] as *const[i8]);
            let mlen=std::cmp::min(len,ipr.0.len());
            #[cfg(target_arch = "x86_64")]
            let _ = &mut cstr[..mlen].copy_from_slice(t_ipr);
            #[cfg(any(target_arch = "aarch64",target_arch = "powerpc"))]
            let _ = &mut cstr[..mlen].copy_from_slice(ipr.0.as_bytes());
        }
    }
}

#[no_mangle]
/// dump ospf route as json message 
pub  extern "C" fn dump_ospf_routes( ospfroute:*mut c_char, len:usize) {
    let rts="".to_owned();
    let mut ospfr=OspfRoutes(rts);
    if show_ospf_routes(&mut ospfr)==0 {
        unsafe {
            let cstr = slice::from_raw_parts_mut(ospfroute, len);
            #[cfg(target_arch = "x86_64")]
            let t_ospfr = &*(ospfr.0.as_bytes() as *const[u8] as *const[i8]);
            let mlen=std::cmp::min(len,ospfr.0.len());
            #[cfg(target_arch = "x86_64")]
            let _ = &mut cstr[..mlen].copy_from_slice(t_ospfr);
            #[cfg(any(target_arch = "aarch64",target_arch = "powerpc"))]
            let _ = &mut cstr[..mlen].copy_from_slice(ospfr.0.as_bytes());
        }
    }
}

#[no_mangle]
/// dump ospf intf as json message 
pub  extern "C" fn dump_ospf_intf( ospfintf:*mut c_char, len:usize) {
    let ints="".to_owned();
    let mut ospfi=OspfInterfaces(ints);
    if show_ospf_int(&mut ospfi)==0 {
        unsafe {
            let cstr = slice::from_raw_parts_mut(ospfintf, len);
            #[cfg(target_arch = "x86_64")]
            let t_ospfi = &*(ospfi.0.as_bytes() as *const[u8] as *const[i8]);
            let mlen=std::cmp::min(len,ospfi.0.len());
            #[cfg(target_arch = "x86_64")]
            let _ = &mut cstr[..mlen].copy_from_slice(t_ospfi);
            #[cfg(any(target_arch = "aarch64",target_arch = "powerpc"))]
            let _ = &mut cstr[..mlen].copy_from_slice(ospfi.0.as_bytes());
        }
    }
}

#[no_mangle]
/// dump ospf info as json message 
pub  extern "C" fn dump_ospf_info( ospfinfo:*mut c_char, len:usize) {
    let infs="".to_owned();
    let mut ospfi=OspfInfo(infs);
    if show_ospf_info(&mut ospfi)==0 {
        unsafe {
            let cstr = slice::from_raw_parts_mut(ospfinfo, len);
            #[cfg(target_arch = "x86_64")]
            let t_ospfi = &*(ospfi.0.as_bytes() as *const[u8] as *const[i8]);
            let mlen=std::cmp::min(len,ospfi.0.len());
            #[cfg(target_arch = "x86_64")]
            let _ = &mut cstr[..mlen].copy_from_slice(t_ospfi);
            #[cfg(any(target_arch = "aarch64",target_arch = "powerpc"))]
            let _ = &mut cstr[..mlen].copy_from_slice(ospfi.0.as_bytes());
        }
    }
}

#[no_mangle]
/// dump ospf neighbor as json message 
pub  extern "C" fn dump_ospf_nei( ospfnei:*mut c_char, len:usize) {
    let ns="".to_owned();
    let mut ospfn=Neighbor(ns);
    if show_ospf_nei(&mut ospfn)==0 {
        unsafe {
            let cstr = slice::from_raw_parts_mut(ospfnei, len);
            #[cfg(target_arch = "x86_64")]
            let t_ospfn = &*(ospfn.0.as_bytes() as *const[u8] as *const[i8]);
            let mlen=std::cmp::min(len,ospfn.0.len());
            #[cfg(target_arch = "x86_64")]
            let _ = &mut cstr[..mlen].copy_from_slice(t_ospfn);
            #[cfg(any(target_arch = "aarch64",target_arch = "powerpc"))]
            let _ = &mut cstr[..mlen].copy_from_slice(ospfn.0.as_bytes());
        }
    }
}

pub  fn show_ip_routes(
    a: &mut IpRoutes,
    ) -> i32 { 
    let runtime = Runtime::new().unwrap();
    //let res = futures::executor::block_on(frr_ospf(&mut *a));
    let res = runtime.block_on(frr_zebra(a));
    let mut retc=-1;
    match res {
        Ok(result_str) => {retc=0;result_str},
        Err(err)=>format!("{}", err.to_string()),
    };
    return retc;
}

pub  fn show_ospf_info(
    a: &mut OspfInfo,
    ) -> i32 { 
    let runtime = Runtime::new().unwrap();
    //let res = futures::executor::block_on(frr_ospf(&mut *a));
    let res = runtime.block_on(frr_ospf(a));
    let mut retc=-1;
    match res {
        Ok(result_str) => {retc=0;result_str},
        Err(err)=>format!("{}", err.to_string()),
    };
    return retc;
}

pub  fn show_ospf_int(
    a: &mut OspfInterfaces,
    ) -> i32 { 
    let runtime = Runtime::new().unwrap();
    //let res = futures::executor::block_on(frr_ospf(&mut *a));
    let res = runtime.block_on(frr_ospf(a));
    let mut retc=-1;
    match res {
        Ok(result_str) => {retc=0;result_str},
        Err(err)=>format!("{}", err.to_string()),
    };
    return retc;
}

pub  fn show_ospf_nei(
    a: &mut Neighbor,
    ) -> i32 { 
    let runtime = Runtime::new().unwrap();
    //let res = futures::executor::block_on(frr_ospf(&mut *a));
    let res = runtime.block_on(frr_ospf(a));
    let mut retc=-1;
    match res {
        Ok(result_str) => {retc=0;result_str},
        Err(err)=>format!("{}", err.to_string()),
    };
    return retc;
}

pub  fn show_ospf_routes(
    a: &mut OspfRoutes,
    ) -> i32 { 
    let runtime = Runtime::new().unwrap();
    //let res = futures::executor::block_on(frr_ospf(&mut *a));
    let res = runtime.block_on(frr_ospf(a));
    let mut retc=-1;
    match res {
        Ok(result_str) => {retc=0;result_str},
        Err(err)=>format!("{}", err.to_string()),
    };
    return retc;
}

async fn frr_zebra<T:Any+Debug>(stru:&mut T) -> Result<String, Box<dyn std::error::Error>> {
    let mut telnet = Telnet::builder()
        .prompt("zebra> ")
        .login_prompt("_", "Password: ")
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1:2601")
        .await?;

    telnet.login("_", "zebra").await?;

    telnet.prompt("zebra# ");
    telnet.execute("enable").await?;
    let value_any = stru as &mut dyn Any;
    match value_any.downcast_mut::<IpRoutes>(){
        Some(rt)=>{
            let res = telnet.execute("show ip route json").await?;
            rt.0=res;
        }
        None=>{
        }
    }

    Ok("".to_owned())
}

async fn frr_static<T:Any+Debug>(stru:&mut T) -> Result<String, Box<dyn std::error::Error>> {
    let mut telnet = Telnet::builder()
        .prompt("staticd> ")
        .login_prompt("_", "Password: ")
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(5))
        .connect("127.0.0.1:2616")
        .await?;

    telnet.login("_", "zebra").await?;

    telnet.prompt("staticd# ");
    telnet.execute("enable").await?;
    let value_any = stru as &mut dyn Any;
    match value_any.downcast_mut::<OspfStaticRoute>(){
        Some(rt)=>{
            let dest_ip_cstr = unsafe{CStr::from_ptr(rt.dest_ipmask)};
            let dest_ip_str = dest_ip_cstr.to_str().unwrap();
            let dest_ip = IPAddress::parse(dest_ip_str);
            if dest_ip.is_ok() {
            }else {
                Err("dest ip address is invalid")?
            }
            if !dest_ip_str.contains("/") {
                Err("dest ip address is invalid(should be with /)")?
            }

            telnet.prompt("staticd(config)# ");
            telnet.execute("conf term").await?;
            if rt.rt_type == 1 {
                let gw_ip_cstr = unsafe{CStr::from_ptr(rt.gateway)};
                let gw_ip_str = gw_ip_cstr.to_str().unwrap();
                let gw_ip = IPAddress::parse(gw_ip_str);
                if gw_ip.is_ok() {
                    if gw_ip_str.contains("/") {
                        Err("1.gateway ip address is invalid")?
                    }

                }else {
                    Err("2.gateway ip address is invalid")?
                }

                if rt.config == 1 {
                    let res = telnet.execute(&format!("ip route {} {}", dest_ip_str, gw_ip_str)).await?;
                    if !result_str_is_ok(&res) {
                        Err(res)?
                    }
                } else if rt.config == 0 {
                    let res = telnet.execute(&format!("no ip route {} {}", dest_ip_str, gw_ip_str)).await?;
                    if !result_str_is_ok(&res) {
                        Err(res)?
                    }

                }
            } else {
                let intf_cstr = unsafe {CStr::from_ptr(rt.intf_name)};
                let intf_str = intf_cstr.to_str().unwrap();
                let (connection, handle, _) = new_connection().unwrap();
                tokio::spawn(connection);
                if let Err(_e) = get_links::get_link_by_name(handle.clone(), intf_str.to_string()).await {
                    Err(format!("{}", _e))?
                }
                if rt.config == 1 {
                    let res = telnet.execute(&format!("ip route {} {}", dest_ip_str, intf_cstr.to_str().unwrap())).await?;
                    if !result_str_is_ok(&res) {
                        Err(res)?
                    }
                } else if rt.config == 0 {
                    let res = telnet.execute(&format!("no ip route {} {}", dest_ip_str, intf_cstr.to_str().unwrap())).await?;
                    if !result_str_is_ok(&res) {
                        Err(res)?
                    }
                }
            }
            telnet.prompt("staticd# ");
            telnet.execute("end").await?;
            return Ok("".to_owned())
        }
        None=>{
        }
    }

    Ok("".to_owned())
}
