use update_client::{ThreatDescriptor, Checksum, FetchResponse};
use errors::*;
use database::*;
use query_client::*;
use atoms::*;

use chan;
use chan::{Sender, Receiver};

use std::collections::HashMap;
use std::thread;
use std::cell::RefCell;

use fibers::{ThreadPoolExecutor, Executor, Spawn};

use fibers::sync::oneshot::Monitor;
use futures;
use futures::future::*;

#[derive(Debug, Clone, Copy)]
pub enum DBState {
    Valid,
    Invalid,
}

#[derive(Clone)]
pub struct DBActor {
    pub channel: (Sender<Atoms>, Receiver<Atoms>),
}

impl DBActor {
    pub fn create<T, H>(mut db: T, executor: H) -> DBActor
        where T: Database,
              H: Spawn + Clone
    {

        let (sender, receiver) = chan::async();

        DBActor::create_and_monitor(sender, receiver, db, &executor).0

    }

    pub fn create_and_monitor<T, H>(sender: Sender<Atoms>,
                                    receiver: Receiver<Atoms>,
                                    mut db: T,
                                    executor: &H)
                                    -> (DBActor, Monitor<(), ErrorKind>)
        where T: Database,
              H: Spawn + Clone
    {

        let receiver_handle = receiver.clone();
        let monitor = executor.spawn_monitor(futures::lazy(move || {
            loop {
                info!("Receiving next message");
                let msg = receiver_handle.recv()
                                         .expect("Sender failed. No one knows the name of this \
                                                  DBActor.");
                match msg {
                    Atoms::DBQuery { hash_prefix, receipt, origin } => {
                        DBActor::query(&mut db, hash_prefix, receipt, origin)
                    }
                    Atoms::Validate { threat_descriptor, checksum, receipt } => {
                        DBActor::validate(&mut db, threat_descriptor, checksum, receipt)
                    }
                    Atoms::Clear { threat_descriptor, receipt } => {
                        DBActor::clear(&mut db, threat_descriptor, receipt)
                    }
                    Atoms::Update { fetch_response, receipt } => {
                        DBActor::update(&mut db, fetch_response, receipt)
                    }
                    _ => panic!("Unexpected msg type"),
                }
            }
            Ok(())
        }));

        (DBActor { channel: (sender, receiver) }, monitor)
    }

    fn query<T>(db: &mut T, hash_prefix: Vec<u8>, receipt: Sender<Atoms>, origin: Sender<Atoms>)
        where T: Database
    {
        info!("Received query message");
        let res = db.query(&hash_prefix[..]).unwrap_or(vec![]);
        // We don't care if they died :)
        let _ = receipt.send(Atoms::DBQueryResponse {
            hash_prefix: hash_prefix,
            result: res,
            origin: origin,
        });
    }

    fn validate<T>(db: &mut T,
                   threat_descriptor: ThreatDescriptor,
                   checksum: Checksum,
                   receipt: Sender<DBState>)
        where T: Database
    {
        info!("Received validate message");
        // We don't care if they died :)
        let _ = match db.validate(threat_descriptor, checksum) {
            Ok(_) => receipt.send(DBState::Valid),
            Err(_) => receipt.send(DBState::Invalid),
        };
    }

    fn clear<T>(db: &mut T, threat_descriptor: ThreatDescriptor, receipt: Sender<Result<()>>)
        where T: Database
    {
        info!("Received clear message");
        let _ = receipt.send(db.clear(threat_descriptor));
    }

    fn update<T>(db: &mut T, response: FetchResponse, receipt: Sender<Result<()>>)
        where T: Database
    {
        info!("Received update message");
        let _ = receipt.send(db.update(&response));
    }
}

fn rand_bool() -> bool {
    use rand;
    let choices = [true, false, false];
    let mut rng = rand::thread_rng();
    *rand::Rng::choose(&mut rng, &choices[..]).unwrap()
}
