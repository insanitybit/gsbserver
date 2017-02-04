use lru::*;
use update_client::ThreatDescriptor;
use database::*;
use errors::*;
use gsburl::*;
use db_actor::*;
use atoms::*;

use std::collections::HashMap;
use std::thread;

use chan;
use chan::{Sender, Receiver};

use fibers::{ThreadPoolExecutor, Executor, Spawn};
use futures;

// This client will attempt to query (in order):
// The database
// The positive and negative caches
// The google safe browsing API

pub struct QueryClient {
    api_key: String,
    // cache: LRU<'a, &'a [u8], ThreatDescriptor>,
    db_actor: Sender<Atoms>,
}

impl QueryClient {
    pub fn process<H: Spawn + Clone>(api_key: String,
                                     db_actor: Sender<Atoms>,
                                     executor: H)
                                     -> Sender<Atoms> {
        let (sender, receiver) = chan::async();


        // Send the cache the url hash + our name + the receipt
        // Cache hit -> Use receipt to send back cached value
        // Cache miss -> Send the database the url hash + our name + the receipt
        //
        let sender_c = sender.clone();

        executor.spawn(futures::lazy(move || {
            let mut client = QueryClient {
                api_key: api_key,
                // cache: LRU::new(10_000),
                db_actor: db_actor,
            };

            loop {
                let msg = receiver.recv().expect("No one has a name for this QueryClient");
                let sender = sender_c.clone();

                match msg {
                    Atoms::Query { url, receipt } => client.query(url, receipt, sender),
                    Atoms::DBQueryResponse { hash_prefix: _, result, origin } => {
                        let _ = origin.send(Atoms::QueryResponse { result: result });
                    }
                    _ => panic!("Unexpected message type"),
                };
            }
            Ok(())
        }));

        sender
    }

    pub fn query(&mut self, url: String, receipt: Sender<Atoms>, this: Sender<Atoms>) {



        let hashes = generate_hashes(&url).unwrap();

        for hash in hashes.keys().cloned() {
            self.db_actor
                .send(Atoms::DBQuery {
                    hash_prefix: hash,
                    receipt: this.clone(),
                    origin: receipt.clone(),
                });
        }
    }
}
