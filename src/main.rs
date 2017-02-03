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
use gsbservice::db_actor::*;
use gsbservice::atoms::*;

use std::collections::HashMap;
use std::sync::mpsc::*;

fn main() {
    env_logger::init().unwrap();
    info!("Service started.");

    main_loop();
}

fn main_loop()  {
    let db = get_db();

    let db_actor = DBActor::start_processing(db);

    GSBUpdater::begin_processing("AIzaSyCB0IE_olGU8GTHhoWnKsRGIKyQszXmr5A".to_owned(), db_actor.clone());

    let query_actor = QueryClient::process("AIzaSyCB0IE_olGU8GTHhoWnKsRGIKyQszXmr5A".to_owned(), db_actor);

    let (send, recv) = channel();


    query_actor.send(Atoms::Query {
        url: "https://google.com/".to_owned(),
        receipt: send
    }).unwrap();

    for msg in recv {
        println!("{:#?}", msg);
    }

    println!("Program exiting gracefully");
}

fn get_db() -> impl Database {
    HashDB::new()
}
