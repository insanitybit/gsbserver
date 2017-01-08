#![allow(dead_code, unused_imports)]
extern crate gsbservice;

use gsbservice::lru;
use gsbservice::update_client::*;

fn main() {
    let mut update_client = UpdateClient::new("AIzaSyCB0IE_olGU8GTHhoWnKsRGIKyQszXmr5A");
    let response = update_client.fetch().send().unwrap();

    let x = response.list_update_responses
                    .iter()
                    .fold(vec![], |mut a, r| {
                        a.extend_from_slice(&r.additions[..]);
                        a
                    });
    // .into_iter()
    // .fold(String::new(), |mut a, s| {
    //     a.push_str(&s.raw_hashes.raw_hashes);
    //     a
    // });

    // let x: Vec<_> = x.split('/')
    //                  .collect();

    // for s in x.iter() {
    //     if s.bytes().len() < 4 || s.bytes().len() > 32 {
    //         println!("invalid hash {}", s);
    //     }
    // }

    println!("{:?}", x);

    let response = update_client.fetch().send().unwrap();

}
