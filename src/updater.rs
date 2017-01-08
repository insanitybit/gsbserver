use update_client::*;
use errors::*;
use database::*;
// use diesel::prelude::*;
// use diesel::pg::PgConnection;
// use dotenv::dotenv;
//
// use rocksdb::DB;

use std::collections::HashMap;
use std::env;
use std::str;

enum CurrentState {
    Running,
    Stopped,
}

// Using the client, fetches updates periodically, storing the results in a database
pub struct GSBUpdater<'a, T>
    where T: Database
{
    update_client: UpdateClient<'a>,
    db: T,
}

impl<'a, T> GSBUpdater<'a, T>
    where T: Database
{
    pub fn new(api_key: &'a str, db: T) -> Result<GSBUpdater<'a, T>> {
        Ok(GSBUpdater {
            update_client: UpdateClient::new(api_key),
            db: db,
        })
    }

    pub fn begin_update(&mut self) -> Result<()> {
        let fetch_response = try!(self.update_client.fetch().send());

        try!(self.db.update(&fetch_response));

        // for (descriptor, hash_prefixes) in &hash_prefix_map {
        //     // self.pg_conn.
        // }
        Ok(())
    }

    pub fn set_period() {
        unimplemented!();
    }

    pub fn stop_updates() {
        unimplemented!();
    }

    pub fn update() -> Result<()> {
        unimplemented!();
    }
}
