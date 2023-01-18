//! `#[component]` Attribute Macro

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    braced,
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    Attribute, Ident, Result, Token, Type, Visibility, WhereClause,
};

/// Type Declaration
pub struct TypeDeclaration {
    /// Attributes
    attrs: Vec<Attribute>,

    /// Visibility
    vis: Visibility,

    /// Unsafety
    unsafety: Option<Token![unsafe]>,

    /// Identifier
    ident: Ident,
}

impl Parse for TypeDeclaration {
    #[inline]
    fn parse(input: ParseStream) -> Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let vis = Visibility::parse(input)?;
        let unsafety = Option::<Token![unsafe]>::parse(input)?;
        <Token![type]>::parse(input)?;
        let ident = Ident::parse(input)?;
        Ok(Self {
            attrs,
            vis,
            unsafety,
            ident,
        })
    }
}

/// Single Component Implementation
pub struct SingleComponentImpl {
    ///
    ident: Ident,

    ///
    body: Type,

    ///
    where_clause: WhereClause,
}

impl Parse for SingleComponentImpl {
    #[inline]
    fn parse(input: ParseStream) -> Result<Self> {
        todo!()
    }
}

/// Component Implementation
pub struct ComponentImpl {
    /// Outer Generics
    outer_generics: Vec<Ident>,

    /// Identifier
    ident: Ident,

    /// Inner Generics
    inner_generics: Vec<Ident>,

    /// Components
    components: Punctuated<SingleComponentImpl, Token![;]>,
}

impl Parse for ComponentImpl {
    #[inline]
    fn parse(input: ParseStream) -> Result<Self> {
        <Token![impl]>::parse(input)?;
        let mut outer_generics = vec![];
        if Option::<Token![<]>::parse(input)?.is_some() {
            outer_generics.push(Ident::parse(input)?);
            loop {
                let lookahead = input.lookahead1();
                if lookahead.peek(Token![,]) {
                    <Token![,]>::parse(input)?;
                    outer_generics.push(Ident::parse(input)?);
                } else if lookahead.peek(Token![>]) {
                    <Token![>]>::parse(input)?;
                    break;
                } else {
                    return Err(lookahead.error());
                }
            }
        }
        let ident = Ident::parse(input)?;
        let mut inner_generics = vec![];
        if !outer_generics.is_empty() {
            <Token![<]>::parse(input)?;
            loop {
                let lookahead = input.lookahead1();
                if lookahead.peek(Token![,]) {
                    <Token![,]>::parse(input)?;
                    inner_generics.push(Ident::parse(input)?);
                } else if lookahead.peek(Token![>]) {
                    <Token![>]>::parse(input)?;
                    break;
                } else {
                    return Err(lookahead.error());
                }
            }
        }
        let content;
        braced!(content in input);
        let components = content.parse_terminated(SingleComponentImpl::parse)?;
        Ok(Self {
            outer_generics,
            ident,
            inner_generics,
            components,
        })
    }
}

/// Component Macro Declaration
pub enum Component {
    /// Basic Type Component
    Type(TypeDeclaration),

    /// Extension Component
    Extension {
        /// Base Declaration
        declaration: TypeDeclaration,

        /// Type Extensions
        extensions: Vec<Ident>,
    },

    /// Component Implementation
    Impl(ComponentImpl),
}

impl Parse for Component {
    #[inline]
    fn parse(input: ParseStream) -> Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(Token![impl]) {
            Ok(Self::Impl(ComponentImpl::parse(input)?))
        } else {
            let declaration = TypeDeclaration::parse(input)?;
            if Option::<Token![:]>::parse(input)?.is_some() {
                let mut extensions = vec![];
                extensions.push(Ident::parse(input)?);
                loop {
                    let lookahead = input.lookahead1();
                    if lookahead.peek(Token![+]) {
                        <Token![+]>::parse(input)?;
                        extensions.push(Ident::parse(input)?);
                    } else if lookahead.peek(Token![;]) {
                        <Token![;]>::parse(input)?;
                        break;
                    } else {
                        return Err(lookahead.error());
                    }
                }
                Ok(Self::Extension {
                    declaration,
                    extensions,
                })
            } else {
                <Token![;]>::parse(input)?;
                Ok(Self::Type(declaration))
            }
        }
    }
}

/// Component Declaration
pub struct Declaration {
    /// Attributes
    attrs: Vec<Attribute>,

    /// Visibility
    vis: Visibility,

    /// Unsafety
    unsafety: Option<Token![unsafe]>,

    /// Identifier
    ident: Ident,

    /// Extension Identifiers
    extensions: Vec<Ident>,
}

impl Parse for Declaration {
    #[inline]
    fn parse(input: ParseStream) -> Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let vis = Visibility::parse(input)?;
        let unsafety = Option::<Token![unsafe]>::parse(input)?;
        Type::parse(input)?;
        let ident = Ident::parse(input)?;
        let mut extensions = vec![];
        if Option::<Token![:]>::parse(input)?.is_some() {
            extensions.push(Ident::parse(input)?);
            loop {
                let lookahead = input.lookahead1();
                if lookahead.peek(Token![+]) {
                    <Token![+]>::parse(input)?;
                    extensions.push(Ident::parse(input)?);
                } else if lookahead.peek(Token![;]) {
                    break;
                } else {
                    return Err(lookahead.error());
                }
            }
        }
        <Token![;]>::parse(input)?;
        Ok(Self {
            attrs,
            vis,
            unsafety,
            ident,
            extensions,
        })
    }
}

/// Transforms a `declaration` component that has no extensions into the `trait` implementation.
#[inline]
fn transform_type(declaration: TypeDeclaration) -> TokenStream {
    let TypeDeclaration {
        attrs,
        vis,
        unsafety,
        ident,
    } = declaration;
    let trait_ident = format_ident!("{}Type", ident);
    let associated_type_doc = "Component Type";
    let type_alias_doc = format!(
        "[`{ident}`]({trait_ident}::{ident}) Type Alias for the [`{trait_ident}`] Component",
    );
    quote!(
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
        impl<T> #trait_ident for &mut T
        where
            T: #trait_ident,
        {
            type #ident = T::#ident;
        }
        #[doc = #type_alias_doc]
        #vis type #ident<T> = <T as #trait_ident>::#ident;
    )
    .into()
}

/// Transforms a `declaration` component with `extensions` into the `trait` implementation.
#[inline]
fn transform_extension(declaration: TypeDeclaration, extensions: Vec<Ident>) -> TokenStream {
    let TypeDeclaration {
        attrs,
        vis,
        unsafety,
        ident,
    } = declaration;
    let trait_ident = format_ident!("{}Types", ident);
    let extensions = extensions
        .into_iter()
        .map(|e| format_ident!("{}Type", e))
        .collect::<Vec<_>>();
    quote!(
        #(#attrs)*
        #vis #unsafety trait #trait_ident: #(#extensions)+* {}
        impl<T> #trait_ident for T
        where
            T: #(#extensions)+*,
        {
        }
    )
    .into()
}

///
#[inline]
fn transform_impl(implementation: ComponentImpl) -> TokenStream {
    let ComponentImpl {
        outer_generics,
        ident,
        inner_generics,
        components,
    } = implementation;

    /*
    TokenStream::from(
        components
            .into_iter()
            .map(|component| quote!())
            .collect::<TokenStream2>(),
    )
    */

    /*
    TokenStream::from(quote!(
        #(
            impl<#(#outer_generics),*>
        )
    ))
    */
    todo!()
}

/// Transforms `args` and `input` according to the macro definition.
#[inline]
pub fn transform(args: TokenStream, input: TokenStream) -> TokenStream {
    let _ = args;
    match parse_macro_input!(input as Component) {
        Component::Type(declaration) => transform_type(declaration),
        Component::Extension {
            declaration,
            extensions,
        } => transform_extension(declaration, extensions),
        Component::Impl(implementation) => transform_impl(implementation),
    }
}
