#![feature(conservative_impl_trait)]
#![allow(dead_code, unused_imports)]
extern crate gsbservice;
extern crate env_logger;

use gsbservice::lru;
use gsbservice::updater::*;
use gsbservice::database::*;

use std::collections::HashMap;

fn main() {
    env_logger::init().unwrap();
    let mut db = get_db();

    std::thread::spawn(move || {
        let mut updater = GSBUpdater::new("AIzaSyCB0IE_olGU8GTHhoWnKsRGIKyQszXmr5A", &mut db);
        loop {
            println!("beginning updating");
            updater.begin_update().unwrap();
        }
    }).join().unwrap();

}

fn get_db() -> impl Database {
    HashDB::new()
}
