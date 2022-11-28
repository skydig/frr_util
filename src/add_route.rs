// SPDX-License-Identifier: MIT

use ipnetwork::Ipv4Network;
use rtnetlink::{new_connection, Error, Handle, IpVersion};
use netlink_packet_route::RouteMessage;
use netlink_packet_route::route::Nla::Gateway;
use netlink_packet_route::route::Nla::Destination;

pub async fn add_route_func(gateway_str:&String, dest_str:&String) -> Result<(), String> {

    let gateway:Result<Ipv4Network,_> = gateway_str.parse();

    if gateway.is_ok() == false {
    }

    let dest: Result<Ipv4Network,_> = dest_str.parse();

    if dest.is_ok() == false {
    }
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    if let Err(e) = add_route(&dest.unwrap(), &gateway.unwrap(), handle.clone()).await {
        Err(e.to_string())?
    }
    Ok(())
}

async fn add_route(dest: &Ipv4Network, gateway: &Ipv4Network, handle: Handle) -> Result<(), Error> {
    let route = handle.route();
    route
        .add()
        .v4()
        .destination_prefix(dest.network(), dest.prefix())
        .gateway(gateway.ip())
        .execute()
        .await?;
    Ok(())
}

fn has_gateway(rm:&RouteMessage) ->(bool, Ipv4Network) {
    for i in rm.nlas.iter() {
        match i {
            Gateway(g) => {
                if g.len() == 4 {
                    return (true,format!("{}.{}.{}.{}",g[0],g[1],g[2],g[3]).parse().unwrap());
                }
            }
            _ =>{}
        }
    }
    (false,"0.0.0.0".parse().unwrap())//("0.0.0.0".to_owned()))
}

fn has_dest(rm:&RouteMessage) ->(bool, Ipv4Network) {
    for i in rm.nlas.iter() {
        match i {
            Destination(d) => {
                if d.len() == 4 {
                   return (true, format!("{}.{}.{}.{}",d[0],d[1],d[2],d[3]).parse().unwrap());
                }
            }
            _ =>{}
        }
    }
    (false,"0.0.0.0".parse().unwrap())//("0.0.0.0".to_owned()))
}

pub async fn del_route_func(gateway_str:&String, dest_str:&String) -> Result<(), String> {

    let gateway:Result<Ipv4Network,_> = gateway_str.parse();

    if gateway.is_ok() == false {
    }

    let dest: Result<Ipv4Network,_> = dest_str.parse();

    if dest.is_ok() == false {
    }

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if let Err(e) = del_route(&dest.unwrap(), &gateway.unwrap(), handle.clone()).await {
        Err(e.to_string())?
    }
    Ok(())
}
use futures::stream::TryStreamExt;
async fn del_route(dest: &Ipv4Network, gateway: &Ipv4Network, handle: Handle) -> Result<(), Error> {
   let del_route = handle.route();
   let mut routes = handle.route().get(IpVersion::V4).execute();
       while let Some(route) = routes.try_next().await? {
           if route.header.address_family == 2 {
                let ( has, g ) =  has_gateway(&route);
                //println!("{:?}",g);
                if !has { 
                    continue 
                } else if &g == gateway {
                    let len = route.header.destination_prefix_length;
                    if dest.prefix() == len {
                        if len == 0 {
                            del_route.del(route).execute().await?;
                            return Ok(());
                        } else {
                            let (has,d) = has_dest(&route);
                            if has {
                                if d.network() == dest.network() {
                                    let _ = del_route.del(route).execute().await?;
                                    return Ok(());
                                }
                            }
                        }
                    }
                }

           }
       } 
    Ok(())
}
