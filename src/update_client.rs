use errors::*;

use hyper::Client;
use hyper::header::Connection;
use hyper::net::HttpsConnector;
use hyper_rustls;

use serde_json;

use std::io::prelude::*;

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct ThreatDescriptor {
//     threat_type: ThreatType,
//     platform_type: PlatformType,
//     threat_entry_type: ThreatEntryType,
// }


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checksum {
    sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RawHashes {
    #[serde(rename = "prefixSize")]
    prefix_size: u32,
    #[serde(rename = "rawHashes")]
    raw_hashes: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RawIndices {
    indices: Vec<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiceDeltaEncoding {
    #[serde(rename = "firstValue")]
    first_value: String,
    #[serde(rename = "riceParameter")]
    rice_parameter: u32,
    #[serde(rename = "numEntries")]
    num_entries: u32,
    #[serde(rename = "encodedData")]
    encoded_data: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntrySet {
    #[serde(rename = "compressionType")]
    compression_type: CompressionType,
    #[serde(default, rename = "rawHashes")]
    raw_hashes: RawHashes,
    #[serde(default, rename = "rawIndices")]
    raw_indices: RawIndices,
    #[serde(default, rename = "riceHashes")]
    rice_hashes: RiceDeltaEncoding,
    #[serde(default, rename = "riceIndices")]
    rice_indices: RiceDeltaEncoding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseType {
    #[serde(rename = "RESPONSE_TYPE_UNSPECIFIED")]
    ResponseTypeUnspecified,
    #[serde(rename = "PARTIAL_UPDATE")]
    PartialUpdate,
    #[serde(rename = "FULL_UPDATE")]
    FullUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    max_database_entries: u32,
    #[serde(rename = "maxUpdateEntries")]
    max_update_entries: u32,
    #[serde(rename = "region")]
    region: Option<&'a str>,
    #[serde(rename = "supportedCompressions")]
    supported_compressions: Vec<CompressionType>,
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
    state: &'a mut Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FetchResponse {
    #[serde(rename = "listUpdateResponses")]
    list_update_responses: Vec<ListUpdateResponse>,
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
    threat_type: ThreatType,
    #[serde(rename = "threatEntryType")]
    threat_entry_type: ThreatEntryType,
    #[serde(rename = "platformType")]
    platform_type: PlatformType,
    #[serde(rename = "responseType")]
    response_type: ResponseType,
    #[serde(default)]
    additions: Vec<ThreatEntrySet>,
    #[serde(default)]
    removals: Vec<ThreatEntrySet>,
    #[serde(rename = "newClientState")]
    new_client_state: String,
    checksum: Checksum,
}


// A client for the Update API
#[derive(Debug)]
pub struct UpdateClient<'a> {
    client_info: ClientInfo<'a>,
    api_client_key: &'a str,
    state: Option<String>,
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
            state: None,
            client: Client::with_connector(HttpsConnector::new(hyper_rustls::TlsClient::new())),
        }
    }

    pub fn fetch(&mut self) -> FetchRequest {
        FetchRequest {
            key: &self.api_client_key,
            client_info: self.client_info.clone(),
            list_update_requests: vec![],
            client: &mut self.client,
            state: &mut self.state,
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
        let cur_state = self.state.clone().unwrap_or("".to_owned());

        if self.list_update_requests.is_empty() {
            self.list_update_requests = default_list_update_requests(cur_state);
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

        *self.state = res.list_update_responses.iter().next().map(|lu| lu.new_client_state.clone());

        Ok(res)
    }
}

fn default_list_update_requests<'a>(state: String) -> Vec<ListUpdateRequest<'a>> {
    vec![ListUpdateRequest {
             state: state.clone(),
             threat_type: ThreatType::Malware,
             platform_type: PlatformType::AnyPlatform,
             threat_entry_type: ThreatEntryType::Url,
             constraints: Constraints::default(),
         },
         ListUpdateRequest {
             state: state.clone(),
             threat_type: ThreatType::SocialEngineering,
             platform_type: PlatformType::AnyPlatform,
             threat_entry_type: ThreatEntryType::Url,
             constraints: Constraints::default(),
         },
         ListUpdateRequest {
             state: state,
             threat_type: ThreatType::UnwantedSoftware,
             platform_type: PlatformType::AnyPlatform,
             threat_entry_type: ThreatEntryType::Url,
             constraints: Constraints::default(),
         }]
}
