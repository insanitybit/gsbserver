use update_client::*;
use errors::*;
use database::*;
// use diesel::prelude::*;
// use diesel::pg::PgConnection;
// use dotenv::dotenv;
//
// use rocksdb::DB;

use std;
use std::time::Duration;
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
    db: &'a T,
    period: u64,
}

unsafe impl<'a, T> Sync for GSBUpdater<'a, T> where T: 'a + Database {}

impl<'a, T> GSBUpdater<'a, T>
    where T: 'a + Database
{
    pub fn new(api_key: &'a str, db: &'a T) -> GSBUpdater<'a, T> {
        GSBUpdater {
            update_client: Arc::new(Mutex::new(UpdateClient::new(api_key))),
            db: db,
            period: 30 * 60,
        }
    }

    pub fn begin_update(&mut self) -> Result<()> {
        let mut update_client = self.update_client.lock().unwrap();

        let fetch_response = update_client.fetch().send().unwrap();
        self.db.update(&fetch_response).unwrap();

        let backoff = Self::parse_backoff(&fetch_response.minimum_wait_duration)
                          .unwrap_or(Duration::from_secs(0));

        info!("Backoff set to: {:#?}", backoff);
        // We have to sleep for the backoff period, or the manual period - whichever is larger
        std::thread::sleep(std::cmp::max(backoff, Duration::from_secs(self.period)));
        Ok(())
    }

    pub fn set_period(&mut self, period: u64) {
        self.period = period;
    }

    // Given a string '123.45s' this will parse into a duration of '153'.
    // 30 seconds is added to any backoff returned
    fn parse_backoff(backoff: &str) -> Option<Duration> {
        if backoff.is_empty() {
            None
        } else {
            let point_ix = backoff.find('.').unwrap();

            let backoff = &backoff[..point_ix];
            let backoff = backoff.parse::<u64>().unwrap();
            Some(Duration::from_secs(backoff + 30))
        }
    }
}
