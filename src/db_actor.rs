use update_client::{ThreatDescriptor, Checksum, FetchResponse};
use errors::*;
use database::*;
use query_client::*;
use atoms::*;

use std::sync::mpsc::*;
use std::collections::HashMap;
use std::thread;

#[derive(Debug, Clone, Copy)]
pub enum DBState {
    Valid,
    Invalid,
}

pub struct DBActor<T>
    where T: Database
{
    inner_db: T,
}

impl<T> DBActor<T>
    where T: Database
{
    pub fn start_processing(db: T) -> Sender<Atoms> {
        let (sender, receiver) = channel();

        thread::spawn(move || {
            let mut db_actor = DBActor { inner_db: db };
            loop {
                info!("Receiving next message");
                let msg = receiver.recv()
                                  .expect("Sender failed. No one knows the name of this DBActor.");
                match msg {
                    Atoms::DBQuery { hash_prefix, receipt, origin } => {
                        db_actor.query(hash_prefix, receipt, origin)
                    }
                    Atoms::Validate { threat_descriptor, checksum, receipt } => {
                        db_actor.validate(threat_descriptor, checksum, receipt)
                    }
                    Atoms::Clear { threat_descriptor, receipt } => {
                        db_actor.clear(threat_descriptor, receipt)
                    }
                    Atoms::Update { fetch_response, receipt } => {
                        db_actor.update(fetch_response, receipt)
                    }
                    _ => panic!("Unexpected msg type"),
                }
            }
        });

        sender
    }

    fn query(&mut self, hash_prefix: Vec<u8>, receipt: Sender<Atoms>, origin: Sender<Atoms>) {
        info!("Received query message");
        let res = self.inner_db.query(&hash_prefix[..]).unwrap_or(vec![]);
        // We don't care if they died :)
        let _ = receipt.send(Atoms::DBQueryResponse {
            hash_prefix: hash_prefix,
            result: res,
            origin: origin,
        });
    }

    fn validate(&mut self,
                threat_descriptor: ThreatDescriptor,
                checksum: Checksum,
                receipt: Sender<DBState>) {
        info!("Received validate message");
        // We don't care if they died :)
        let _ = match self.inner_db.validate(threat_descriptor, checksum) {
            Ok(_) => receipt.send(DBState::Valid),
            Err(_) => receipt.send(DBState::Invalid),
        };
    }

    fn clear(&mut self, threat_descriptor: ThreatDescriptor, receipt: Sender<Result<()>>) {
        info!("Received clear message");
        let _ = receipt.send(self.inner_db.clear(threat_descriptor));
    }

    fn update(&mut self, response: FetchResponse, receipt: Sender<Result<()>>) {
        info!("Received update message");
        let _ = receipt.send(self.inner_db.update(&response));
    }
}
