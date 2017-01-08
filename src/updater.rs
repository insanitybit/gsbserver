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
use std::thread;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

enum CurrentState {
    Running,
    Stopped,
}

// Using the client, fetches updates periodically, storing the results in a database
pub struct GSBUpdater<'a, T>
    where T: 'a + Database
{
    update_client: Arc<Mutex<UpdateClient<'a>>>,
    db: &'a mut T,
    period: usize, // 30 seconds - will be 30 minutes later...
    thread: Option<thread::JoinHandle<Result<()>>>,
    should_execute: AtomicBool,
}

impl<'a, T> GSBUpdater<'a, T>
    where T: Database
{
    pub fn new(api_key: &'a str, db: &'a mut T) -> Result<GSBUpdater<'a, T>> {
        Ok(GSBUpdater {
            update_client: Arc::new(Mutex::new(UpdateClient::new(api_key))),
            db: db,
            period: 30,
            thread: None,
            should_execute: AtomicBool::new(false),
        })
    }

    pub fn begin_update(&mut self) -> Result<()> {
        self.thread = Some(thread::spawn(|| {
            loop {
                let update_client = self.update_client.lock().unwrap();

                let fetch_response = try!(update_client.fetch().send());

                try!(self.db.update(&fetch_response));

            }
        }));
        Ok(())
    }

    pub fn set_period() {
        unimplemented!();
    }

    pub fn stop_updates() {
        unimplemented!();
    }
}
