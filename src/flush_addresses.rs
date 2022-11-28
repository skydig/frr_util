// SPDX-License-Identifier: MIT

use futures::stream::TryStreamExt;
use rtnetlink::{new_connection, Error, Handle};

pub async fn flush_addresses_func(link_name:&String) -> Result<(), String> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if let Err(e) = flush_addresses(handle, link_name).await {
       Err(e.to_string())?
    }

    Ok(())
}

async fn flush_addresses(handle: Handle, link: &String) -> Result<(), Error> {
    let mut links = handle.link().get().match_name(link.clone()).execute();
    if let Some(link) = links.try_next().await? {
        assert!(links.try_next().await?.is_none());

        let mut addresses = handle
            .address()
            .get()
            .set_link_index_filter(link.header.index)
            .execute();
        while let Some(addr) = addresses.try_next().await? {
            handle.address().del(addr).execute().await?;
        }
        Ok(())
    } else {
        eprintln!("link {} not found", link);
        Ok(())
    }
}

