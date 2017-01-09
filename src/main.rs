#![feature(conservative_impl_trait)]
#![allow(dead_code, unused_imports)]

#[macro_use]
extern crate lazy_static;

extern crate gsbservice;
extern crate env_logger;

use gsbservice::lru;
use gsbservice::updater::*;
use gsbservice::database::*;

use std::collections::HashMap;

fn main() {
    env_logger::init().unwrap();

    let db = get_db();
    let db2 = db.clone();

    let background_thread = std::thread::spawn(move || {
        let mut updater = GSBUpdater::new("AIzaSyCB0IE_olGU8GTHhoWnKsRGIKyQszXmr5A", &db2);
        loop {
            updater.begin_update().unwrap();
        }
    });

    background_thread.join()
    .unwrap();

}

fn get_db() -> impl Database {
    HashDB::new()
}
