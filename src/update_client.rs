use errors::*;

use hyper::Client;
use hyper::header::Connection;
use hyper::net::HttpsConnector;
use hyper_rustls;

use serde_json;

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct ThreatDescriptor {
//     threat_type: ThreatType,
//     platform_type: PlatformType,
//     threat_entry_type: ThreatEntryType,
// }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlatformType {
    PlatformTypeUnspecified,
    Windows,
    Linux,
    Android,
    Osx,
    Ios,
    AnyPlatform,
    AllPlatforms,
    Chrome,
}

#[derive(Debug, Clone, Serialize, Deserialize, Serialize, Deserialize)]
pub enum ThreatEntryType {
    ThreatEntryTypeUnspecified,
    Url,
    Executable,
    IpRange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    ThreatTypeUnspecified,
    Malware,
    SocialEngineering,
    UnwantedSoftware,
    PotentiallyHarmfulApplication,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupportCompression {
    Unspecified,
    Raw,
    Rice, // Unimplemented
}

/// https://developers.google.com/safe-browsing/v4/reference/rest/v4/threatListUpdates/fetch#Constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints<'a> {
    max_database_entries: u32,
    max_update_entries: u32,
    region: Option<&'a str>,
    supported_compressions: Vec<SupportCompression>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FetchRequest<'a> {
    client_info: ClientInfo<'a>,
    list_update_requests: Vec<ListUpdateRequest<'a>>,
    #[serde(skip_serializing, skip_deserializing)]
    client: &'a mut Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchResponse {

}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo<'a> {
    client_version: &'static str,
    client_id: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListUpdateRequest<'a> {
    state: &'a str,
    threat_type: ThreatType,
    platform_type: PlatformType,
    threat_entry_type: ThreatEntryType,
    constraints: Constraints<'a>,
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
            client_info: self.client_info.clone(),
            list_update_requests: vec![],
            client: &mut self.client,
        }
    }
}

impl<'a> Default for Constraints<'a> {
    fn default() -> Constraints<'a> {
        Constraints {
            max_database_entries: 0,
            max_update_entries: 0,
            region: None,
            supported_compressions: vec![SupportCompression::Raw],
        }
    }
}

impl<'a> FetchRequest<'a> {
    pub fn send(&mut self) -> Result<FetchResponse> {
        const url: &'static str = "https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch";
        let body = serde_json::to_string(&self);

        // self.client
        //     .post()
        //     .body("");

        unimplemented!()
    }
}

fn default_list_update_requests<'a>() -> Vec<ListUpdateRequest<'a>> {
    vec![ListUpdateRequest {
             state: "",
             threat_type: ThreatType::Malware,
             platform_type: PlatformType::AnyPlatform,
             threat_entry_type: ThreatEntryType::Url,
             constraints: Constraints::default(),
         },
         ListUpdateRequest {
             state: "",
             threat_type: ThreatType::SocialEngineering,
             platform_type: PlatformType::AnyPlatform,
             threat_entry_type: ThreatEntryType::Url,
             constraints: Constraints::default(),
         },
         ListUpdateRequest {
             state: "",
             threat_type: ThreatType::UnwantedSoftware,
             platform_type: PlatformType::AnyPlatform,
             threat_entry_type: ThreatEntryType::Url,
             constraints: Constraints::default(),
         }]
}
