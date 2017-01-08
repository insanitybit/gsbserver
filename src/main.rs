#![feature(conservative_impl_trait)]
#![allow(dead_code, unused_imports)]
extern crate gsbservice;

use gsbservice::lru;
use gsbservice::updater::*;
use gsbservice::database::*;

use std::collections::HashMap;

fn main() {
    let mut db = get_db();

    let mut updater = GSBUpdater::new("AIzaSyCB0IE_olGU8GTHhoWnKsRGIKyQszXmr5A", &mut db)
    .unwrap();

    updater.begin_update().unwrap();
}

fn get_db() -> impl Database {
    HashDB::new()
}
