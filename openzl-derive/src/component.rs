//! `#[component]` Attribute Macro

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    token::{Semi, Type, Unsafe},
    Attribute, Ident, Result, Visibility,
};

/// Component Declaration
pub struct Declaration {
    /// Attributes
    attrs: Vec<Attribute>,

    /// Visibility
    vis: Visibility,

    /// Unsafety
    unsafety: Option<Unsafe>,

    /// Identifier
    ident: Ident,
}

impl Parse for Declaration {
    #[inline]
    fn parse(input: ParseStream) -> Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let vis = Visibility::parse(input)?;
        let unsafety = Option::<Unsafe>::parse(input)?;
        Type::parse(input)?;
        let ident = Ident::parse(input)?;
        Semi::parse(input)?;
        Ok(Self {
            attrs,
            vis,
            unsafety,
            ident,
        })
    }
}

/// Transforms `args` and `input` according to the macro definition.
#[inline]
pub fn transform(args: TokenStream, input: TokenStream) -> TokenStream {
    let _ = args;
    let Declaration {
        attrs,
        vis,
        unsafety,
        ident,
    } = parse_macro_input!(input as Declaration);
    let trait_ident = format_ident!("{}Type", ident);
    let associated_type_doc = "Component Type";
    let type_alias_doc = format!(
        "[`{}`]({trait_ident}::{ident}) Type Alias for the [`{}`] Trait",
        ident, trait_ident
    );
    TokenStream::from(quote!(
        #(#attrs)*
        #vis #unsafety trait #trait_ident {
            #[doc = #associated_type_doc]
            type #ident;
        }

        impl<T> #trait_ident for &T
        where
            T: #trait_ident,
        {
            type #ident = T::#ident;
        }

        #[doc = #type_alias_doc]
        #vis type #ident<T> = <T as #trait_ident>::#ident;
    ))
}
