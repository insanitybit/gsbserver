use lru::*;
use update_client::ThreatDescriptor;
use database::*;
use errors::*;
use gsburl::*;
use db_actor::*;
use query_client::*;
use update_client::*;

use std::sync::mpsc::*;

#[derive(Debug, Clone)]
pub enum Atoms {
    DBQuery {
        hash_prefix: Vec<u8>,
        receipt: Sender<Atoms>,
        origin: Sender<Atoms>,
    },
    Validate {
        threat_descriptor: ThreatDescriptor,
        checksum: Checksum,
        receipt: Sender<DBState>,
    },
    Clear {
        threat_descriptor: ThreatDescriptor,
        receipt: Sender<Result<()>>,
    },
    Update {
        fetch_response: FetchResponse,
        receipt: Sender<Result<()>>,
    },
    Query {
        url: String,
        receipt: Sender<Atoms>,
    },
    QueryResponse {
        result: Vec<ThreatDescriptor>,
    },
    DBQueryResponse {
        hash_prefix: Vec<u8>,
        result: Vec<ThreatDescriptor>,
        origin: Sender<Atoms>,
    },
}
