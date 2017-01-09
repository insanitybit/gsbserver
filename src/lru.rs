use std::collections::HashMap;
use std::time::*;
use std::hash::Hash;

// A cache that allows for per-value timeout invalidation

pub enum LRUEntry<T> {
    Present(T),
    Expired,
    Vacant,
}

pub struct LRU<K: Hash + Eq, T> {
    cache: HashMap<K, (T, Instant, Duration)>,
}

impl<K, T> LRU<K, T>
    where K: Hash + Eq
{
    pub fn new() -> LRU<K, T> {
        LRU { cache: HashMap::new() }
    }

    pub fn insert(&mut self, key: K, val: T, lifespan: Duration) {
        self.cache.insert(key, (val, Instant::now(), lifespan));
    }

    pub fn get(&mut self, key: &K) -> LRUEntry<&T> {
        let (val, then, lifespan) = match self.cache.get(key) {
            Some(&(ref val, then, lifespan)) => (val as *const T, then, lifespan),
            None => return LRUEntry::Vacant,
        };

        if Self::is_timed_out(then, lifespan) {
            self.cache.remove(key);
            // self.cache.take(key)
            LRUEntry::Expired
        } else {
            LRUEntry::Present(unsafe { &*val })
        }
    }

    fn is_timed_out(then: Instant, dur: Duration) -> bool {
        let age = then.elapsed();
        if age >= dur {
            false
        } else {
            true
        }
    }
}
