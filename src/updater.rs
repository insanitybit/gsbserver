use update_client::*;
use errors::*;
use database::*;
use db_actor::*;
use atoms::*;

use std;
use std::time::Duration;
use std::collections::HashMap;
use std::env;
use std::str;
use std::thread;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Mutex};

use chan;
use chan::{Sender, Receiver};

use fibers::{ThreadPoolExecutor, Executor, Spawn};
use futures;

enum CurrentState {
    Running,
    Stopped,
}

// Using the client, fetches updates periodically, storing the results in a database
pub struct GSBUpdater {
    update_client: UpdateClient,
    db_actor: Sender<Atoms>,
    period: u64,
}

impl GSBUpdater {
    pub fn begin_processing<H>(api_key: String, db_actor: Sender<Atoms>, executor: H)
        where H: Spawn + Clone
    {

        let (sender, receiver) = chan::async();

        executor.spawn(futures::lazy(move || {
            let mut updater = GSBUpdater {
                update_client: UpdateClient::new(api_key),
                db_actor: db_actor,
                period: 30 * 60,
            };

            loop {
                let fetch_response = updater.update_client
                                            .fetch()
                                            .send()
                                            .expect("Failed to send fetch request");

                let minimum_wait_duration = fetch_response.minimum_wait_duration.clone();

                info!("Sending database update");
                updater.db_actor
                       .send(Atoms::Update {
                           fetch_response: fetch_response,
                           receipt: sender.clone(),
                       });

                info!("Awaiting db update status");
                receiver.recv()
                        .expect("No one knows this GSBUpdater's name")
                        .expect("Database failed to update!");

                info!("Validating database (JK)");

                let backoff = Self::parse_backoff(&minimum_wait_duration)
                                  .expect("Failed to parse backoff")
                                  .unwrap_or(Duration::from_secs(0));

                info!("Backoff set to: {:#?}", backoff);
                // We have to sleep for the backoff period, or the manual period - whichever is larger
                std::thread::sleep(std::cmp::max(backoff, Duration::from_secs(updater.period)));

            }
            Ok(())
        }));
    }

    pub fn set_period(&mut self, period: u64) {
        self.period = period;
    }

    // Given a string '123.45s' this will parse into a duration of '153'.
    // 30 seconds is added to any backoff returned
    fn parse_backoff(backoff: &str) -> Result<Option<Duration>> {
        if backoff.is_empty() {
            Ok(None)
        } else {
            let point_ix = backoff.find('.').unwrap_or(backoff.len() - 1);
            // We know this can't panic because the minimum value of point_ix is 0.
            // When the second value to a non inclusive slice is 0, an empty slice is returned.
            let backoff = &backoff[..point_ix];
            let backoff = try!(backoff.parse::<u64>()
                                      .chain_err(|| "Failed to parse backoff into an integer"));
            Ok(Some(Duration::from_secs(backoff + 30)))
        }
    }
}
