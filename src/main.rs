#![feature(conservative_impl_trait)]
#![allow(dead_code, unused_imports)]

#[macro_use]
extern crate log;

extern crate gsbservice;
extern crate env_logger;

#[macro_use]
extern crate error_chain;

use gsbservice::errors::*;
use gsbservice::lru;
use gsbservice::updater::*;
use gsbservice::database::*;
use gsbservice::query_client::*;

use std::collections::HashMap;

fn main() {
    env_logger::init().unwrap();
    info!("Service started.");

    main_loop();
}

fn main_loop()  {
    let db = get_db();
    let db2 = db.clone();
    let db3 = db.clone();

    let mut query_client = QueryClient::new("AIzaSyCB0IE_olGU8GTHhoWnKsRGIKyQszXmr5A", &db3);



    let background_updater = std::thread::spawn(move || {
        let mut updater = GSBUpdater::new("AIzaSyCB0IE_olGU8GTHhoWnKsRGIKyQszXmr5A", &db2);
        loop {
            updater.begin_update().expect("Update failed");
        }
    });

    let query_client.query("https://google.com/").unwrap();



    background_updater.join().unwrap();

}

fn get_db() -> impl Database {
    HashDB::new()
}
