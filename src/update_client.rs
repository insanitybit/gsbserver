use errors::*;

use hyper::Client;
use hyper::header::Connection;
use hyper::net::HttpsConnector;
use hyper_rustls;

use serde_json;

use std::io::prelude::*;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Copy)]
pub struct ThreatDescriptor {
    pub threat_type: ThreatType,
    pub platform_type: PlatformType,
    pub threat_entry_type: ThreatEntryType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checksum {
    pub sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RawHashes {
    #[serde(rename = "prefixSize")]
    pub prefix_size: u32,
    #[serde(rename = "rawHashes")]
    pub raw_hashes: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RawIndices {
    pub indices: Vec<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiceDeltaEncoding {
    #[serde(rename = "firstValue")]
    pub first_value: String,
    #[serde(rename = "riceParameter")]
    pub rice_parameter: u32,
    #[serde(rename = "numEntries")]
    pub num_entries: u32,
    #[serde(rename = "encodedData")]
    pub encoded_data: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntrySet {
    #[serde(rename = "compressionType")]
    pub compression_type: CompressionType,
    #[serde(default, rename = "rawHashes")]
    pub raw_hashes: RawHashes,
    #[serde(default, rename = "rawIndices")]
    pub raw_indices: RawIndices,
    #[serde(default, rename = "riceHashes")]
    pub rice_hashes: RiceDeltaEncoding,
    #[serde(default, rename = "riceIndices")]
    pub rice_indices: RiceDeltaEncoding,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ResponseType {
    #[serde(rename = "RESPONSE_TYPE_UNSPECIFIED")]
    ResponseTypeUnspecified,
    #[serde(rename = "PARTIAL_UPDATE")]
    PartialUpdate,
    #[serde(rename = "FULL_UPDATE")]
    FullUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Copy)]
pub enum PlatformType {
    #[serde(rename = "PLATFORM_TYPE_UNSPECIFIED")]
    PlatformTypeUnspecified,
    #[serde(rename = "WINDOWS")]
    Windows,
    #[serde(rename = "LINUX")]
    Linux,
    #[serde(rename = "ANDROID")]
    Android,
    #[serde(rename = "OSX")]
    Osx,
    #[serde(rename = "IOS")]
    Ios,
    #[serde(rename = "ANY_PLATFORM")]
    AnyPlatform,
    #[serde(rename = "ALL_PLATFORMS")]
    AllPlatforms,
    #[serde(rename = "CHROME")]
    Chrome,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Copy)]
pub enum ThreatEntryType {
    #[serde(rename = "THREAT_ENTRY_TYPE_UNSPECIFIED")]
    ThreatEntryTypeUnspecified,
    #[serde(rename = "URL")]
    Url,
    #[serde(rename = "EXECUTABLE")]
    Executable,
    #[serde(rename = "IP_RANGE")]
    IpRange,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Copy)]
pub enum ThreatType {
    #[serde(rename = "THREAT_TYPE_UNSPECIFIED")]
    ThreatTypeUnspecified,
    #[serde(rename = "MALWARE")]
    Malware,
    #[serde(rename = "SOCIAL_ENGINEERING")]
    SocialEngineering,
    #[serde(rename = "UNWANTED_SOFTWARE")]
    UnwantedSoftware,
    #[serde(rename = "POTENTIALLY_HARMFUL_APPLICATION")]
    PotentiallyHarmfulApplication,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionType {
    #[serde(rename = "UNSPECIFIED")]
    Unspecified,
    #[serde(rename = "RAW")]
    Raw,
    #[serde(rename = "RICE")]
    Rice, // Unimplemented
}

/// https://developers.google.com/safe-browsing/v4/reference/rest/v4/threatListUpdates/fetch#Constraints
#[derive(Debug, Clone, Serialize)]
pub struct Constraints<'a> {
    #[serde(rename = "maxDatabaseEntries")]
    pub max_database_entries: u32,
    #[serde(rename = "maxUpdateEntries")]
    pub max_update_entries: u32,
    #[serde(rename = "region")]
    pub region: Option<&'a str>,
    #[serde(rename = "supportedCompressions")]
    pub supported_compressions: Vec<CompressionType>,
}

#[derive(Debug, Serialize)]
pub struct FetchRequest<'a> {
    #[serde(skip_serializing)]
    key: &'a str,
    #[serde(rename = "client")]
    client_info: ClientInfo<'a>,
    #[serde(rename = "listUpdateRequests")]
    list_update_requests: Vec<ListUpdateRequest<'a>>,
    #[serde(skip_serializing)]
    client: &'a Client,
    #[serde(skip_serializing)]
    state_map: &'a mut HashMap<(PlatformType, ThreatEntryType, ThreatType), String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FetchResponse {
    #[serde(rename = "listUpdateResponses")]
    pub list_update_responses: Vec<ListUpdateResponse>,
    #[serde(default, rename = "minimumWaitDuration")]
    pub minimum_wait_duration: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientInfo<'a> {
    #[serde(rename = "clientVersion")]
    client_version: &'static str,
    #[serde(rename = "clientId")]
    client_id: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListUpdateRequest<'a> {
    state: String,
    #[serde(rename = "threatType")]
    threat_type: ThreatType,
    #[serde(rename = "platformType")]
    platform_type: PlatformType,
    #[serde(rename = "threatEntryType")]
    threat_entry_type: ThreatEntryType,
    constraints: Constraints<'a>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListUpdateResponse {
    #[serde(rename = "threatType")]
    pub threat_type: ThreatType,
    #[serde(rename = "threatEntryType")]
    pub threat_entry_type: ThreatEntryType,
    #[serde(rename = "platformType")]
    pub platform_type: PlatformType,
    #[serde(rename = "responseType")]
    pub response_type: ResponseType,
    #[serde(default)]
    pub additions: Vec<ThreatEntrySet>,
    #[serde(default)]
    pub removals: Vec<ThreatEntrySet>,
    #[serde(rename = "newClientState")]
    pub new_client_state: String,
    pub checksum: Checksum,
}


// A client for the Update API
#[derive(Debug)]
pub struct UpdateClient<'a> {
    client_info: ClientInfo<'a>,
    api_client_key: &'a str,
    state_map: HashMap<(PlatformType, ThreatEntryType, ThreatType), String>,
    client: Client,
}

impl<'a> UpdateClient<'a> {
    pub fn new(api_key: &str) -> UpdateClient {
        UpdateClient {
            client_info: ClientInfo {
                client_version: "0.0.1",
                client_id: "RustGSB4Server",
            },
            api_client_key: api_key,
            state_map: HashMap::default(),
            client: Client::with_connector(HttpsConnector::new(hyper_rustls::TlsClient::new())),
        }
    }

    pub fn fetch(&mut self) -> FetchRequest {
        FetchRequest {
            key: &self.api_client_key,
            client_info: self.client_info.clone(),
            list_update_requests: vec![],
            client: &mut self.client,
            state_map: &mut self.state_map,
        }
    }
}

impl<'a> Default for Constraints<'a> {
    fn default() -> Constraints<'a> {
        Constraints {
            max_database_entries: 0,
            max_update_entries: 0,
            region: None,
            supported_compressions: vec![CompressionType::Raw],
        }
    }
}

impl<'a> FetchRequest<'a> {
    pub fn send(&mut self) -> Result<FetchResponse> {
        let url = "https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch".to_owned() +
                  "?key=" + self.key;

        if self.list_update_requests.is_empty() {
            self.list_update_requests = default_list_update_requests(self.state_map);
        }

        let body = try!(serde_json::to_string(&self).chain_err(|| {
            format!("Failed to serialize FestRequest body: {:#?}", &self)
        }));

        let mut res = try!(self.client
                               .post(&url)
                               .body(&body)
                               .send()
                               .chain_err(|| {
                                   format!("Failed to send fetch request to {:#?}", url)
                               }));

        let res: FetchResponse = {
            let mut buf = Vec::new();
            try!(res.read_to_end(&mut buf)
                    .chain_err(|| {
                        format!("Failed to read response into buffer for fetch request.")
                    }));

            try!(serde_json::from_slice(&buf[..])
                     .chain_err(|| format!("Failed to deserialize response into FetchResponse.")))
        };

        for response in &res.list_update_responses {
            let new_state = response.new_client_state.clone();
            self.state_map
                .insert((response.platform_type, response.threat_entry_type, response.threat_type),
                        new_state);
        }

        Ok(res)
    }
}

fn default_list_update_requests<'a>(state_map: &HashMap<(PlatformType,
                                                         ThreatEntryType,
                                                         ThreatType),
                                                        String>)
                                    -> Vec<ListUpdateRequest<'a>> {

    let state_a = state_map.get(&(PlatformType::AnyPlatform,
                                  ThreatEntryType::Url,
                                  ThreatType::Malware))
                           .unwrap_or(&"".to_owned())
                           .clone();
    info!("state_a: {:#?}", state_a);
    let state_b = state_map.get(&(PlatformType::AnyPlatform,
                                  ThreatEntryType::Url,
                                  ThreatType::SocialEngineering))
                           .unwrap_or(&"".to_owned())
                           .clone();
    info!("state_b: {:#?}", state_b);
    let state_c = state_map.get(&(PlatformType::AnyPlatform,
                                  ThreatEntryType::Url,
                                  ThreatType::UnwantedSoftware))
                           .unwrap_or(&"".to_owned())
                           .clone();
    info!("state_c: {:#?}", state_c);
    vec![ListUpdateRequest {
             state: state_a,
             threat_type: ThreatType::Malware,
             platform_type: PlatformType::AnyPlatform,
             threat_entry_type: ThreatEntryType::Url,
             constraints: Constraints::default(),
         },
         ListUpdateRequest {
             state: state_b,
             threat_type: ThreatType::SocialEngineering,
             platform_type: PlatformType::AnyPlatform,
             threat_entry_type: ThreatEntryType::Url,
             constraints: Constraints::default(),
         },
         ListUpdateRequest {
             state: state_c,
             threat_type: ThreatType::UnwantedSoftware,
             platform_type: PlatformType::AnyPlatform,
             threat_entry_type: ThreatEntryType::Url,
             constraints: Constraints::default(),
         }]
}
