#![feature(conservative_impl_trait)]
#![allow(dead_code, unused_imports)]

#[macro_use]
extern crate log;

#[macro_use]
extern crate chan;


extern crate gsbservice;
extern crate env_logger;

extern crate fibers;
extern crate futures;

#[macro_use]
extern crate error_chain;

use gsbservice::errors::*;
use gsbservice::lru;
use gsbservice::updater::*;
use gsbservice::database::*;
use gsbservice::supervisor::*;
use gsbservice::query_client::*;
use gsbservice::db_actor::*;
use gsbservice::atoms::*;

use fibers::{ThreadPoolExecutor, Executor};

use std::collections::HashMap;
use std::sync::mpsc::*;


fn main() {
    env_logger::init().unwrap();
    info!("Service started.");

    main_loop();
}

fn main_loop()  {

    let executor = ThreadPoolExecutor::new().unwrap();

    let handle = executor.handle();

    let tmp_handle = handle.clone();
    let db_actor = DBSupervisor::new(handle.clone(), move |sender, receiver| {
        DBActor::create_and_monitor(sender, receiver, get_db(), &tmp_handle)
    });

    GSBUpdater::begin_processing("AIzaSyCB0IE_olGU8GTHhoWnKsRGIKyQszXmr5A".to_owned(), db_actor.channel.0.clone(),
handle.clone());

    let query_actor = QueryClient::process("AIzaSyCB0IE_olGU8GTHhoWnKsRGIKyQszXmr5A".to_owned(), db_actor.channel.0,
handle);

    let (send, _) = chan::async();

    for _ in 0..100 {

        query_actor.send(Atoms::Query {
            url: "https://google.com/".to_owned(),
            receipt: send.clone()
        });
    }

    let _ = executor.run();


    println!("Program exiting gracefully");
}

fn get_db() -> impl Database {
    HashDB::new()
}
