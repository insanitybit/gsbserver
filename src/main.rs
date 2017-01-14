#![feature(conservative_impl_trait)]
#![allow(dead_code, unused_imports)]

#[macro_use]
extern crate log;

extern crate gsbservice;
extern crate env_logger;

use gsbservice::lru;
use gsbservice::updater::*;
use gsbservice::database::*;

use std::collections::HashMap;

fn main() {
    env_logger::init().unwrap();
    info!("Start!");
    let db = get_db();


    loop {
        let db2 = db.clone();

        let background_thread = std::thread::spawn(move || {
            let mut updater = GSBUpdater::new("AIzaSyCB0IE_olGU8GTHhoWnKsRGIKyQszXmr5A", &db2);
            loop {
                updater.begin_update().expect("Update failed");
            }
        });

        if let Err(e) = background_thread.join() {
            error!("Restarting background_thread. {:#?}", e);
            std::thread::sleep(std::time::Duration::from_secs(30));
        };
    }
}

fn get_db() -> impl Database {
    HashDB::new()
}
