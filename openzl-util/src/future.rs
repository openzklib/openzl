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

//! Futures Utilities

#[cfg(feature = "alloc")]
use {
    alloc::boxed::Box,
    core::{future::Future, pin::Pin},
};

/// Box Future
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub type BoxFuture<'f, T = ()> = Pin<Box<dyn 'f + Future<Output = T> + Send>>;

/// Box Future Result
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub type BoxFutureResult<'f, T, E> = BoxFuture<'f, Result<T, E>>;

/// Local Box Future
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub type LocalBoxFuture<'f, T = ()> = Pin<Box<dyn 'f + Future<Output = T>>>;

/// Local Box Future Result
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub type LocalBoxFutureResult<'f, T, E> = LocalBoxFuture<'f, Result<T, E>>;
