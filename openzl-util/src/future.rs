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
