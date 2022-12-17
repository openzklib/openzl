//! Merkle Trees and Forests

// FIXME: Get rid of as many `pub(super)` declarations as we can.
// TODO:  Should `Leaf` move into `Tree`/`Configuration` since we might want the tree to have
//        special kinds of leaf input (metadata along with just the digest)?
// TODO:  Maybe we should require `INNER_HEIGHT` instead of `HEIGHT` so that we don't have to rely
//        on the user to check that `HEIGHT >= 2`.
// TODO:  Extend to arbitrary arity.

mod node;
mod tree;

pub mod forest;
pub mod fork;
pub mod full;
pub mod inner_tree;
pub mod partial;
pub mod path;
pub mod single_path;

#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test;

pub use node::*;
pub use path::prelude::*;
pub use tree::*;
