// Copyright 2019-2022 Manta Network.
// This file is part of manta-rs.
//
// manta-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

//! Selection Iterator

use alloc::vec::Vec;
use crossbeam_channel::{Receiver, Select};

#[cfg(feature = "rayon")]
use {
    crossbeam_channel::{self as channel, Sender},
    rayon::Scope,
};

/// Selection Task
#[cfg(feature = "rayon")]
struct Task<I>
where
    I: Iterator,
{
    /// Underlying Iterator
    iter: I,

    /// Item Sender
    sender: Sender<I::Item>,

    /// Task Queue Sender
    queue: Sender<Self>,
}

#[cfg(feature = "rayon")]
impl<I> Task<I>
where
    I: Iterator,
{
    /// Builds a new [`Task`] for selecting from `iter` and sending along `sender`.
    #[inline]
    fn new(iter: I, sender: Sender<I::Item>, queue: &Sender<Self>) -> Self {
        Self {
            iter,
            sender,
            queue: queue.clone(),
        }
    }

    /// Sends the next element in the iterator to its receiver, and enqueue `self` onto the task
    /// queue if sending was successful.
    #[inline]
    fn send_next(mut self) {
        if let Some(item) = self.iter.next() {
            if self.sender.send(item).is_ok() {
                let _ = self.queue.clone().send(self);
            }
        }
    }
}

/// Parallel Selection Iterator
#[derive(Debug)]
pub struct SelectAll<T> {
    /// Receivers
    receivers: Vec<Receiver<T>>,
}

impl<T> SelectAll<T> {
    /// Builds a new [`SelectAll`] from a set of [`Receiver`] over `T`.
    #[inline]
    pub fn new(receivers: Vec<Receiver<T>>) -> Self {
        Self { receivers }
    }

    /// Builds a new [`SelectAll`] iterator over `iters` in the parallel execution context `scope`.
    #[cfg(feature = "rayon")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "rayon")))]
    #[inline]
    pub fn spawn<'s, S, I>(iterators: S, scope: &Scope<'s>) -> Self
    where
        T: Send,
        S: IntoIterator<Item = I>,
        S::IntoIter: ExactSizeIterator,
        I: IntoIterator<Item = T>,
        I::IntoIter: 's + Send,
    {
        let iterators = iterators.into_iter();
        let len = iterators.len();
        let (queue, listener) = channel::bounded(len);
        let mut receivers = Vec::with_capacity(len);
        for iter in iterators {
            let (sender, receiver) = channel::unbounded();
            queue
                .send(Task::new(iter.into_iter(), sender, &queue))
                .expect(
                    "This send is guaranteed to succeed because we have access to the receiver.",
                );
            receivers.push(receiver);
        }
        scope.spawn(move |scope| {
            while let Ok(task) = listener.recv() {
                scope.spawn(|_| task.send_next());
            }
        });
        Self::new(receivers)
    }

    /// Returns the number of live receivers.
    #[inline]
    pub fn len(&self) -> usize {
        self.receivers.len()
    }

    /// Returns `true` if there are no more live receivers.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Iterator for SelectAll<T> {
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let len = self.receivers.len();
        if len == 0 {
            return None;
        }
        let mut drop_indices = Vec::<usize>::with_capacity(len);
        let mut select = Select::new();
        for receiver in &self.receivers {
            select.recv(receiver);
        }
        loop {
            let index = select.ready();
            match self.receivers[index].try_recv() {
                Ok(item) => {
                    drop_indices.sort_unstable_by(move |l, r| r.cmp(l));
                    drop_indices.dedup();
                    for index in drop_indices {
                        self.receivers.remove(index);
                    }
                    return Some(item);
                }
                Err(e) if e.is_disconnected() => {
                    drop_indices.push(index);
                    select.remove(index);
                    if drop_indices.len() == len {
                        self.receivers.clear();
                        return None;
                    }
                }
                _ => {}
            }
        }
    }
}
