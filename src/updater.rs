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
use std::sync::atomic::{AtomicBool, AtomicUsize};
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
    period: AtomicUsize,
    thread: Option<thread::JoinHandle<Result<()>>>,
    should_execute: AtomicBool,
}

impl<'a, T> GSBUpdater<'a, T>
    where T: 'a + Database
{
    pub fn new(api_key: &'a str, db: &'a mut T) -> Result<GSBUpdater<'a, T>> {
        Ok(GSBUpdater {
            update_client: Arc::new(Mutex::new(UpdateClient::new(api_key))),
            db: db,
            period: AtomicUsize::new(30), // 30 seconds - will be 30 minutes later...+
            thread: None,
            should_execute: AtomicBool::new(false),
        })
    }

    pub fn begin_update(&'a mut self) -> Result<()> {
        self.thread = Some(thread::spawn(move || {
            loop {
                let update_client = self.update_client.lock().unwrap();

                let fetch_response = update_client.fetch().send().unwrap();

                self.db.update(&fetch_response).unwrap();

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
