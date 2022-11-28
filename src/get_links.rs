// SPDX-License-Identifier: MIT
#![allow(dead_code,unused_imports)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use futures::stream::TryStreamExt;
use rtnetlink::{
    new_connection,
    packet::rtnl::{
        constants::{AF_BRIDGE, RTEXT_FILTER_BRVLAN},
        link::nlas::Nla,
    },
    Error,
    Handle,
};

pub async fn dump_links_func() -> Result<Vec<(String,u32, u32)>, Error> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    Ok(dump_links(handle.clone()).await?)
}

async fn get_link_by_index(handle: Handle, index: u32) -> Result<(), Error> {
    let mut links = handle.link().get().match_index(index).execute();
    let msg = if let Some(msg) = links.try_next().await? {
        msg
    } else {
        eprintln!("no link with index {} found", index);
        return Ok(());
    };
    // We should have received only one message
    assert!(links.try_next().await?.is_none());

    for nla in msg.nlas.into_iter() {
        if let Nla::IfName(name) = nla {
            println!("found link with index {} (name = {})", index, name);
            return Ok(());
        }
    }
    eprintln!(
        "found link with index {}, but this link does not have a name",
        index
    );
    Ok(())
}

pub async fn get_link_by_name(handle: Handle, name: String) -> Result<(), Error> {
    let mut links = handle.link().get().match_name(name.clone()).execute();
    if (links.try_next().await?).is_some() {
        assert!(links.try_next().await?.is_none());
    } else {
    }
    Ok(())
}

async fn dump_links(handle: Handle) -> Result<Vec<(String,u32, u32)>, Error> {
    let mut links = handle.link().get().execute();
    let mut res=Vec::new();
    while let Some(msg) = links.try_next().await? {
            let idx=msg.header.index;
            let mut imtu=0;
            let mut iname="".to_owned();
        for nla in msg.nlas.into_iter() {
            if let Nla::IfName(name) = nla {
                iname = name;
            }else if let Nla::Mtu(mtu) = nla {
                imtu = mtu;
            }
        }
        res.push((iname, idx, imtu));
    }
    Ok(res)
}

async fn dump_bridge_filter_info(handle: Handle) -> Result<(), Error> {
    let mut links = handle
        .link()
        .get()
        .set_filter_mask(AF_BRIDGE as u8, RTEXT_FILTER_BRVLAN)
        .execute();
    'outer: while let Some(msg) = links.try_next().await? {
        for nla in msg.nlas.into_iter() {
            if let Nla::AfSpecBridge(data) = nla {
                println!(
                    "found interface {} with AfSpecBridge data {:?})",
                    msg.header.index, data
                );
                continue 'outer;
            }
        }
    }
    Ok(())
}
