use update_client::*;
use errors::*;

use std;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};


pub trait Database {
    fn update(&mut self, &FetchResponse) -> Result<()>;
}

pub struct HashDB {
    inner_db: Arc<Mutex<HashMap<ThreatDescriptor, Vec<String>>>>,
}

impl HashDB {
    pub fn new() -> HashDB {
        HashDB { inner_db: Arc::new(Mutex::new(HashMap::new())) }
    }


    fn remove(&mut self,
              removal_map: &HashMap<ThreatDescriptor, (ResponseType, HashSet<usize>)>)
              -> Result<()> {

        for (descriptor, &(_response_type, ref removals)) in removal_map {
            if removals.is_empty() {
                continue;
            }

            let mut cur_map = self.inner_db.lock().expect("Failed to attain lock for inner_db");

            let cur_hashes = match cur_map.get_mut(descriptor) {
                Some(h) => h,
                None => continue,
            };

            let new_hashes: Vec<String> = cur_hashes.iter()
                                                    .enumerate()
                                                    .filter_map(|(ix, s)| {
                                                        if removals.contains(&ix) {
                                                            Some(s.clone())
                                                        } else {
                                                            None
                                                        }
                                                    })
                                                    .collect();

            *cur_hashes = new_hashes;
        }

        Ok(())
    }
}

impl Database for HashDB {
    fn update(&mut self, res: &FetchResponse) -> Result<()> {
        let rem_indices = try!(removals(res));

        let add_prefixes = try!(additions(res));

        try!(self.remove(&rem_indices));

        // for (descriptor, (response_type, additions)) in add_prefixes {
        //     if additions.is_empty() {
        //         continue;
        //     }
        //
        // }

        Ok(())
    }
}

fn additions(fetch_response: &FetchResponse)
             -> Result<HashMap<ThreatDescriptor, (ResponseType, Vec<String>)>> {

    let mut threat_map = HashMap::new();

    for response in &fetch_response.list_update_responses {
        let mut hash_prefixes = Vec::new();

        // Each set of additions will contain a string. This string is the concatenated list of
        // hash prefixes. In a single 'addition' threat entry the prefix size is the same for all
        // hashes, but the prefix size may vary across threat entries.
        for threat_entry in &response.additions {
            if let CompressionType::Raw = threat_entry.compression_type {

                let raw_hashes = &threat_entry.raw_hashes;

                let init = raw_hashes.raw_hashes.as_bytes();
                let mut ix = 0;
                loop {
                    if ix == init.len() {
                        break;
                    }

                    let char_slice =
                        try!(String::from_utf8(init[ix..ix + raw_hashes.prefix_size as usize]
                                                   .to_vec())
                                 .chain_err(|| "could not convert hash to utf8 string"));
                    ix = ix + raw_hashes.prefix_size as usize;
                    hash_prefixes.push(char_slice);
                }
            }
        }
        hash_prefixes.sort();
        threat_map.insert(ThreatDescriptor {
                              threat_type: response.threat_type,
                              platform_type: response.platform_type,
                              threat_entry_type: response.threat_entry_type,
                          },
                          (response.response_type, hash_prefixes));
    }
    Ok(threat_map)
}

fn removals(fetch_response: &FetchResponse)
            -> Result<HashMap<ThreatDescriptor, (ResponseType, HashSet<usize>)>> {

    let mut threat_map = HashMap::new();

    for response in &fetch_response.list_update_responses {
        let mut raw_indices = HashSet::new();

        for threat_entry in &response.removals {
            if let CompressionType::Raw = threat_entry.compression_type {

                for raw in threat_entry.raw_indices.indices.clone() {
                    raw_indices.insert(raw);
                }
            }
        }

        threat_map.insert(ThreatDescriptor {
                              threat_type: response.threat_type,
                              platform_type: response.platform_type,
                              threat_entry_type: response.threat_entry_type,
                          },
                          (response.response_type, raw_indices));
    }
    Ok(threat_map)
}
