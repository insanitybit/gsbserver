use chan::{Sender, Receiver};
use errors::*;

use futures;
use futures::{Future, future};
use fibers::{Executor, ThreadPoolExecutor, Spawn};
use fibers::sync::oneshot::Monitor;
use atoms::*;
use db_actor::*;
use std::sync::Arc;
use chan;

#[derive(Clone)]
pub struct DBSupervisor {
    channel: (Sender<Atoms>, Receiver<Atoms>),
}

impl DBSupervisor {
    pub fn new<F, H>(exec: H,
                  new_actor: F)
                  -> DBActor
        where F: Send + 'static + Fn(Sender<Atoms>, Receiver<Atoms>) -> (DBActor, Monitor<(), ErrorKind>),
        H: Spawn + Clone
    {

        let (sender, receiver) = chan::async();
        let sender_handle = sender.clone();
        let receiver_handle = receiver.clone();

        let super_monitor: Monitor<(), ErrorKind> = exec.spawn_monitor(futures::lazy(move || {
            info!("Starting new actor");
            loop {
                let (actor, monitor) = new_actor(sender_handle.clone(), receiver_handle.clone());
                monitor.wait();
                info!("Restarting actor");
            }
            Ok(())
        }));

        DBActor { channel: (sender, receiver) }
    }
}
