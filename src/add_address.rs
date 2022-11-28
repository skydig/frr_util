// SPDX-License-Identifier: MIT
#![allow(dead_code,unused_imports)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use futures::stream::TryStreamExt;
use std::env;

use ipnetwork::IpNetwork;
use rtnetlink::{new_connection, Error, Handle};

//#[tokio::main]
pub async fn add_address_func(link_name:&str, ip:IpNetwork) -> Result<(), String> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if let Err(e) = add_address(link_name, ip, handle.clone()).await {
        Err(e.to_string())?
    }
    Ok(())
}

async fn add_address(link_name: &str, ip: IpNetwork, handle: Handle) -> Result<(), Error> {
    let mut links = handle
        .link()
        .get()
        .match_name(link_name.to_string())
        .execute();
    if let Some(link) = links.try_next().await? {
        handle
            .address()
            .add(link.header.index, ip.ip(), ip.prefix())
            .execute()
            .await?
    }
    Ok(())
}
