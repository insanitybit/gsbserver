#![feature(custom_derive, i128_type)]

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
#[macro_use]
extern crate maplit;
#[macro_use]
extern crate lazy_static;
// extern crate dotenv;
extern crate lru_cache;

extern crate hyper_rustls;
extern crate hyper;
extern crate crypto;
extern crate base64;
// extern crate rocksdb;
extern crate serde_json;
extern crate stopwatch;
extern crate regex;
extern crate url;
extern crate idna;

pub mod errors;
pub mod lru;
pub mod update_client;
pub mod query_client;
pub mod updater;
pub mod database;
pub mod gsburl;
