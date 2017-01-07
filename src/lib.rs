#![feature(custom_derive, custom_attribute)]
#![allow(dead_code, unused_imports, non_upper_case_globals)]
#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde;

extern crate serde_json;

extern crate hyper_rustls;
extern crate hyper;

pub mod errors;
pub mod lru;
pub mod update_client;
pub mod updater;
