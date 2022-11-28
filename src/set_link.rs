// SPDX-License-Identifier: MIT

use futures::stream::TryStreamExt;
use rtnetlink::{new_connection, Error, Handle};

//#[tokio::main]
pub async fn set_link_up_down_func(link_name:&str, down:bool) -> Result<(), String> {

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    set_link_up_down(handle, link_name.to_string(), down)
        .await
        .map_err(|e| format!("{}", e))
}

async fn set_link_up_down(handle: Handle, name: String, down:bool) -> Result<(), Error> {
    let mut links = handle.link().get().match_name(name.clone()).execute();
    if let Some(link) = links.try_next().await? {
	if down  {
          handle
            .link()
            .set(link.header.index)
            .down()
            .execute()
            .await?
	} else {
          handle
            .link()
            .set(link.header.index)
	    .up()
            .execute()
            .await?
	}
    } else {
        println!("no link link {} found", name);
    }
    Ok(())
}

pub async fn set_link_promisc_func(link_name:&str, promisc:i32) -> Result<(), String> {
    
    if promisc != 1 && promisc != 0 {
        Err("paramster error")?
    }
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    set_link_promisc(handle, link_name.to_string(), promisc)
        .await
        .map_err(|e| format!("{}", e))
}
async fn set_link_promisc(handle: Handle, name: String, promisc:i32) -> Result<(), Error> {
    let mut links = handle.link().get().match_name(name.clone()).execute();
    if let Some(link) = links.try_next().await? {
	if promisc == 1{
          handle
            .link()
            .set(link.header.index)
            .promiscuous(true)
            .execute()
            .await?
	} else if  promisc == 0 {
          handle
            .link()
            .set(link.header.index)
            .promiscuous(false)
            .execute()
            .await?
	} else {
        return Ok(());
    }
    } else {
        println!("no link link {} found", name);
    }
    Ok(())
}

pub async fn set_link_mtu_func(link_name:&str, mtu:u32) -> Result<(), String> {

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    set_link_mtu(handle, link_name.to_string(), mtu)
        .await
        .map_err(|e| format!("{}", e))
}
async fn set_link_mtu(handle: Handle, name: String, mtu:u32) -> Result<(), Error> {
    let mut links = handle.link().get().match_name(name.clone()).execute();
    if let Some(link) = links.try_next().await? {
          handle
            .link()
            .set(link.header.index)
            .mtu(mtu)
            .execute()
            .await?
    } else {
        println!("no link link {} found", name);
    }
    Ok(())
}
