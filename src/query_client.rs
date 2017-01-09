use lru::LRU;
use update_client::ThreatDescriptor;
use database::*;

// This client will attempt to query (in order):
// The database
// The positive and negative caches
// The google safe browsing API

pub struct QueryClient<'a, T>
    where T: 'a + Database
{
    api_key: &'a str,
    cache: LRU<&'a str, ThreatDescriptor>,
    db: &'a T,
}

impl<'a, T> QueryClient<'a, T>
    where T: 'a + Database
{
    pub fn new(api_key: &'a str, db: &'a T) -> QueryClient<'a, T> {
        QueryClient {
            api_key: api_key,
            cache: LRU::new(),
            db: db,
        }
    }
}
