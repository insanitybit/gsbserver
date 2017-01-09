#![feature(custom_derive)]

#![allow(dead_code, unused_imports, non_upper_case_globals)]
#![recursion_limit = "1024"]

// #[macro_use]
// extern crate diesel;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate log;
// extern crate dotenv;
extern crate hyper_rustls;
extern crate hyper;
extern crate crypto;
extern crate base64;
// extern crate rocksdb;
extern crate serde_json;

pub mod errors;
pub mod lru;
pub mod update_client;
pub mod query_client;
pub mod updater;
pub mod database;
