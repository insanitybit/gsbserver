#![allow(dead_code, unused_imports)]
extern crate gsbservice;

use gsbservice::lru;
use gsbservice::updater::*;
use gsbservice::database::*;

use std::collections::HashMap;

fn main() {
    let mut updater = GSBUpdater::new("AIzaSyCB0IE_olGU8GTHhoWnKsRGIKyQszXmr5A", HashDB::new());
}
