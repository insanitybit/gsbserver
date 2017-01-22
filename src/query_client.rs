use lru::*;
use update_client::ThreatDescriptor;
use database::*;
use errors::*;
use gsburl::*;

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
            cache: LRU::new(10_000),
            db: db,
        }
    }

    pub fn query(&mut self, url: &str) -> Result<Vec<ThreatDescriptor>> {

        let hashes = generate_hashes(url).unwrap();
        let mut descriptors = Vec::with_capacity(hashes.len());

        for hash in hashes.keys() {
            match self.cache.get(&hash) {
                LRUEntry::Present(h) => descriptors.push(h),
                _ => continue,
            }
        }

        unimplemented!();
    }
}
