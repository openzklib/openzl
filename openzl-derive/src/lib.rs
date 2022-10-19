//! OpenZL Attribute and Derive Macros
//!
//! See [openzl](https://docs.rs/openzl) for documentation on how to use these macros.

extern crate proc_macro;

use proc_macro::TokenStream;

mod component;

/// Defines a _component type_.
///
/// # Component Types
///
/// A component type is a trait and type alias.
#[proc_macro_attribute]
pub fn component(args: TokenStream, input: TokenStream) -> TokenStream {
    component::transform(args, input)
}
