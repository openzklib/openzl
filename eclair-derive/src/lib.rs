//! **ECLAIR** Attribute and Derive Macros
//!
//! See [eclair](https://docs.rs/eclair) for documentation on how to use these macros.

extern crate proc_macro;

mod alias;

use proc_macro::TokenStream;

/// Creates an _alias type_.
///
/// # Alias Types
///
/// An alias type is a trait and type alias.
#[proc_macro_attribute]
pub fn alias(args: TokenStream, input: TokenStream) -> TokenStream {
    alias::transform(args, input)
}
