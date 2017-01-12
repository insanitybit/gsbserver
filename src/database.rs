use update_client::*;
use errors::*;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use base64::*;
use std;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};


pub trait Database: Send + Sync + Clone {
    fn query(&self, &str, ThreatDescriptor) -> Result<Option<()>>;
    fn update(&self, &FetchResponse) -> Result<()>;
    fn validate(&self, &FetchResponse) -> Result<()>;
}

#[derive(Clone)]
pub struct HashDB {
    inner_db: Arc<Mutex<HashMap<ThreatDescriptor, Vec<String>>>>,
}

impl HashDB {
    pub fn new() -> HashDB {
        HashDB { inner_db: Arc::new(Mutex::new(HashMap::new())) }
    }


    fn remove(&self,
              removal_map: &HashMap<ThreatDescriptor, (ResponseType, HashSet<usize>)>)
              -> Result<()> {

        for (descriptor, &(_response_type, ref removals)) in removal_map {
            if removals.is_empty() {
                continue;
            }

            info!("Removing {:#?} from {:#?}", removals.len(), descriptor);

            let mut cur_map = self.inner_db.lock().expect("Failed to attain lock for inner_db");

            let mut cur_hashes = cur_map.entry(*descriptor)
                                        .or_insert(vec![]);

            cur_hashes.sort();
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

    fn add(&self,
           addition_map: &HashMap<ThreatDescriptor, (ResponseType, Vec<String>)>)
           -> Result<()> {

        for (descriptor, &(response_type, ref additions)) in addition_map {
            if additions.is_empty() {
                continue;
            }
            info!("Adding {:#?} to {:#?}", additions.len(), descriptor);
            let mut cur_map = self.inner_db.lock().expect("Failed to attain lock for inner_db");

            if let ResponseType::PartialUpdate = response_type {

                let mut cur_hashes = cur_map.entry(*descriptor)
                                            .or_insert(vec![]);

                cur_hashes.extend_from_slice(&additions[..]);

                cur_hashes.sort();
            } else if let ResponseType::FullUpdate = response_type {
                cur_map.insert(*descriptor, additions.clone());
            }
        }

        Ok(())
    }
}

impl Database for HashDB {
    fn update(&self, res: &FetchResponse) -> Result<()> {
        let rem_indices = try!(removals(res));
        let add_prefixes = try!(additions(res));

        try!(self.remove(&rem_indices));
        try!(self.add(&add_prefixes));

        Ok(())
    }

    fn validate(&self, res: &FetchResponse) -> Result<()> {
        for response in &res.list_update_responses {
            let descriptor = ThreatDescriptor {
                threat_type: response.threat_type,
                platform_type: response.platform_type,
                threat_entry_type: response.threat_entry_type,
            };
            let checksum = &response.checksum;

            let mut hash = {
                let mut cur_map = self.inner_db.lock().expect("Failed to attain lock for inner_db");

                let cur_hashes = match cur_map.get_mut(&descriptor) {
                    Some(h) => h,
                    None => {
                        info!("Could not get hashes for descriptor: {:#?}", descriptor);
                        continue;
                    }
                };

                cur_hashes.sort();
                cur_hashes.dedup();

                cur_hashes.iter()
                          .fold(Sha256::new(), |mut s, r| {
                              s.input(r.as_bytes());
                              s
                          })
            };

            let result = {
                hash.input(&vec![]);
                let mut result = vec![0; 32];
                hash.result(&mut result);
                result
            };
            let hash = result;

            if hash != checksum.sha256.as_bytes() {
                error!("Checksum failed {:?} != {:?}",
                       hash,
                       checksum.sha256.as_bytes());
            } else {
                info!("Database validated");
            }

        }

        Ok(())
    }

    fn query(&self, _url: &str, _descriptor: ThreatDescriptor) -> Result<Option<()>> {
        unimplemented!()
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

                if raw_hashes.raw_hashes.len() % raw_hashes.prefix_size as usize != 0 {
                    error!("Raw hashes not divisible by prefix_size. Skipping update.");
                    continue;
                }

                let hash_count = raw_hashes.raw_hashes.len() / raw_hashes.prefix_size as usize;
                hash_prefixes.reserve(hash_count);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update() {
        let db = HashDB::new();
        let res = fetch_req();

        db.update(&res);
    }


    // Given an empty local database the database should recieve
    // a full update of hashes as well as a sha256 checksum
    // Assert that the checksum is as expected.

    #[test]
    fn test_additions() {
        let res = fetch_req();
        let addition_map = additions(&res).unwrap();

        assert_eq!(addition_map.get(&ThreatDescriptor {
                                   threat_type: ThreatType::Malware,
                                   platform_type: PlatformType::Linux,
                                   threat_entry_type: ThreatEntryType::Url,
                               })
                               .unwrap()
                               .1,
                   vec!["1234", "5678"]);
    }

    fn fetch_req() -> FetchResponse {

        let update_res = ListUpdateResponse {
            threat_type: ThreatType::Malware,
            threat_entry_type: ThreatEntryType::Url,
            platform_type: PlatformType::Linux,
            response_type: ResponseType::FullUpdate,
            additions: vec![ThreatEntrySet {
                                compression_type: CompressionType::Raw,
                                raw_hashes: RawHashes {
                                    prefix_size: 4,
                                    raw_hashes: "12345678".to_owned(),
                                },
                                raw_indices: RawIndices { indices: vec![] },
                                rice_hashes: RiceDeltaEncoding {
                                    first_value: "".to_owned(),
                                    rice_parameter: 0,
                                    num_entries: 0,
                                    encoded_data: "".to_owned(),
                                },
                                rice_indices: RiceDeltaEncoding {
                                    first_value: "".to_owned(),
                                    rice_parameter: 0,
                                    num_entries: 0,
                                    encoded_data: "".to_owned(),
                                },
                            }],
            removals: vec![],
            new_client_state: "new_state".to_owned(),
            checksum: Checksum { sha256: "".to_owned() },
        };

        FetchResponse {
            list_update_responses: vec![update_res],
            minimum_wait_duration: "300.4s".to_owned(),
        }
    }
    //

}
