#![allow(dead_code, unused_imports)]
extern crate gsbservice;

use gsbservice::lru;
use gsbservice::update_client::*;

fn main() {
    let mut update_client = UpdateClient::new("AIzaSyCB0IE_olGU8GTHhoWnKsRGIKyQszXmr5A");
    let response = update_client.fetch().send().unwrap();

    let x: usize = response.list_update_responses.iter().map(|r| r.additions.len()).sum();

    println!("{:?}", x);

    let response = update_client.fetch().send().unwrap();
    let x: usize = response.list_update_responses.iter().map(|r| r.additions.len()).sum();


    println!("{:?}", x);


}
