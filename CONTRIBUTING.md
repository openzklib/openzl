# Contributing

Thank you for contributing to the OpenZL codebase! Here are some guidelines to follow when adding code or documentation to this repository.

## Use Conventional Commits

Please use conventional commits. We use at least the following types:

- `feat`: adding a new feature, new functionality to the codebase
- `fix`: fixing old code
- `chore`: small changes/commits that are left over from other commits
- `wip`: marked whenever a commit should be considered part of a set of commits that together implement a feature or fix

See the [conventional commits specification](https://www.conventionalcommits.org) for more details on how to write and use conventional commits. We use squashing for our PRs so we can add types to commits and reformat them according to the spec if you forget to include them. 

## Changelog

We use the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) specification for [`CHANGELOG.md`](./CHANGELOG.md). Whenever we add a new PR we want to make sure to add **one** line to the changelog with the following format:

```text
- [\#3](https://github.com/openzklib/openzl/pull/3) Migrate some of OpenZL from the Manta-Network codebase
```

in any of the relevant categories outlined in the changelog spec:

- `Added` for new features.
- `Changed` for changes in existing functionality.
- `Deprecated` for soon-to-be removed features.
- `Removed` for now removed features.
- `Fixed` for any bug fixes.
- `Security` in case of vulnerabilities.

Like the rest of the specification entails, all changes should be presented in reverse-chronological order. To label a PR as belonging to any one of these categories for inclusion in the GitHub auto-generated release notes, use the following labels:

- `L-added`
- `L-changed`
- `L-deprecated`
- `L-removed`
- `L-fixed`
- `L-security`

to place each PR in its respective category or use `L-skip` if it should not be included in the GitHub auto-generated release notes.

## Pull Requests

### Templates

We use pull-request templates to standardize the PR process. See the [`PULL_REQUEST_TEMPLATE.md`](./.github/PULL_REQUEST_TEMPLATE.md) for more details on how to build a good PR.

### CI Pipeline

When writing a new PR, the Continuous Integration (CI) system will trigger linting and tests to run on every commit. See the [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) for more detail on this workflow.

## Style Guide

To keep code and documentation style consistent across all the code in the repository, we are adopting the following style guide. We begin with the formatting style enforced by the Nightly version of `rustfmt` with configuration specified in the [`.rustfmt.toml`](./.rustfmt.toml) file. Beyond what `rustfmt` currently enforces we have specified other rules below.

### The `Cargo.toml` File

The `Cargo.toml` file should ahere to the following template:

```toml
[package]
name = "..."
version = "..."
edition = "..."
readme = "README.md"
license = "MIT OR Apache-2.0"
repository = "https://github.com/openzklib/openzl"
homepage = "https://openzl.org"
documentation = "..."
categories = ["..."]
keywords = ["..."]
description = "..."

[package.metadata.docs.rs]
# To build locally:
# RUSTDOCFLAGS="--cfg doc_cfg" cargo +nightly doc --all-features --open
all-features = true
rustdoc-args = ["--cfg", "doc_cfg"]

[badges]
is-it-maintained-issue-resolution = { repository = "openzklib/openzl" }
is-it-maintained-open-issues = { repository = "opezklib/openzl" }
maintenance = { status = "actively-developed" }

[[bin]]
...

[features]
...

[dependencies]
...

[dev-dependencies]
...

[build-dependencies]
...

[profile....]
...
```

Specifically, we have:

1. Use double quotes instead of single quotes.
2. Use the above as the standard ordering of the `[package]` map.
3. `[[bin]]` before `[features]` before `[dependencies]` before `[dev-dependencies]` before `[build-dependencies]` before `[profile]` settings.
4. Order features and dependencies alphabetically.
5. When selecting features for a `[features]` entry or when selecting the features on a dependency, order the features alphabetically.
6. For a given dependency use the following structure with `optional` and `features` keys as needed:
    ```toml
    crate-name = { version = "...", optional = true, default-features = false, features = ["..."] }
    ```
    If the crate is a `path` or `git` dependency, replace those keys with the `version` key and add a `tag`, `branch`, or `rev` as needed following the `git` key.
7. When adding a feature, add a doc string in title case and a newline between each feature.

### Feature Selection

When using features, be sure to attach a `doc_cfg` feature declaration as well unless the code is not exported to `pub`.

```rust
#[cfg(feature = "...")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "...")))]
pub mod feature_gated_public_module;
```

### Imports and Exports

Imports (`use`) and exports (`mod`) should be ordered as follows:

1. External Crate Declarations
2. Private Imports
3. Private Imports with Features
4. Private Exports
5. Private Exports with Features
6. Public Exports
7. Public Exports with Features
8. Reexports
9. Reexports with Features

Here's an example set of declarations:

```rust
extern crate crate_name;

use module::submodule::entry;

#[cfg(feature = "...")]
use module::feature_gated_submodule;

mod another_module;
mod module;
mod the_third_module;

#[cfg(feature = "...")]
mod feature_gated_module;

pub mod public_module;

#[cfg(feature = "...")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "...")))]
pub mod feature_gated_public_module;

pub use reexported_objects;

#[cfg(feature = "...")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "...")))]
pub use feature_gated_reexported_objects;
```

Ensure that there are newlines between each category. Be sure that if there are imports or exports that are feature-gated, that they are sorted by feature alphabetically. If there is a feature gated import that requires importing multiple objects use the following pattern:

```rust
#[cfg(feature = "...")]
use {
    thing1, thing2, thing3, thing4,
};
```

**NOTE**: All imports should occur at the top of any module and a newline should be added between the last import and the first declared object.

### Traits

#### Defining Traits

When defining a trait use the following syntax:

```rust
/// DOCS
trait Trait<T> {
    /// DOCS
    type Type1: Default;

    /// DOCS
    type Type2;

    /// DOCS
    const CONST_1: usize;

    /// DOCS
    const CONST_2: usize;

    /// DOCS
    fn required_method(&self, argument: Self::Type1) -> T;

    /// DOCS
    #[inline]
    fn optional_method(&self) -> T {
        Self::required_method(Self::Type1::default())
    }
}
```

Notice the ordering of components:

1. Associated Types
2. Associated Constants
3. Methods

Depending on the context and presentation, you can mix the ordering of required and optional methods. Also, notice the name formatting, although `clippy` should detect if naming differs from this pattern.

#### Implementing Traits

When implementing traits use the following syntax:

```rust
impl<T> Trait for Struct<T> {
    type Type1 = B;
    type Type2 = C;

    const CONST_1: usize = 3;
    const CONST_2: usize = 4;

    #[inline]
    fn required_method(&self, argument: Self::Type1) -> T {
        self.struct_method(argument).clone()
    }

    #[inline]
    fn optional_method(&self) -> T {
        short_cut_optimization(self)
    }
}
```

Notice the lack of space between implementaions of the same category except for methods which always get a newline between them (like all methods). Only add space between types and constants if a comment is necessary like in this example:

```rust
impl Configuration {
    const SPECIAL_CONSTANT: usize = 1234249;

    /// In this case we have to use this constant because it's very special.
    const ANOTHER_SPECIAL_CONSTANT: usize = 10000023;
}
```

but otherwise it should look like

```rust
impl Configuration {
    const SPECIAL_CONSTANT: usize = 1234249;
    const ANOTHER_SPECIAL_CONSTANT: usize = 10000023;
}
```

### Crate `lib.rs` Module

Every crate has at least a `lib.rs` (or a `main.rs` if there is no library) and it should include at least these macro invocations:

```rust
//! Module Documentation

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![forbid(rustdoc::broken_intra_doc_links)]
#![forbid(missing_docs)]

// IMPORTS AND EXPORTS GO HERE
```

or with `#![no_std]` instead of the first macro if there is no `std` feature.

### Ignoring Compiler Warnings

In certain cases we may want to ignore a particular compiler warning or `clippy` warning. This is especially true in because of some false-positive error or because we are writing some generic macro code. In either case we need to mark the `#[allow(...)]` clause with a note on why we want to ignore this warning. 

```rust
#[allow(clippy::some_lint)] // NOTE: Here's the reason why this is ok.
fn some_function() {}
```

In the case of `allow` we want to be careful of it's scope so as to not ignore warnings except in the exact place where the unexpected behavior exists. Therefore, `#[allow(...)]` should be marked on functions and not modules, even if that means it is repeated multiple times. In some rare cases where this repetition would be too cumbersome, and adding it to the module is cleaner, then also be sure to state in a note why this is better than marking it on the functions themselves.

#### The `lint_reasons` Feature

This kind of pattern will eventually be enforced by `clippy` itself, but is currently an unstable feature. See [allow_attributes_without_reason](https://rust-lang.github.io/rust-clippy/master/index.html#allow_attributes_without_reason) and [rust-lang/rust/54503](https://github.com/rust-lang/rust/issues/54503) for more information. Once it is stable we can move to this pattern.

### Where Clauses

1. Always use where clauses instead of inline trait constraints. So instead of

    ```text
    fn function<T: Clone>(t: &T) -> T {
        t.clone()
    }
    ```

    you should use

    ```rust
    fn function<T>(t: &T) -> T
    where
        T: Clone,
    {
        t.clone()
    }
    ```

    This is also true for any part of the code where generic types can be declared, like in `fn`, `struct`, `enum`, `trait`, and `impl`. The only "exception" is for supertraits, so use:

    ```rust
    trait Trait: Clone + Default + Sized {}
    ```

    instead of using

    ```text
    trait Trait
    where
        Self: Clone + Default + Sized,
    {}
    ```

2. Order `where` clause entries by declaration order, then by associated types and then by other constraints. Here's an example

    ```rust
    fn function<A, B, C>(a: &A, b: &mut B) -> Option<C>
    where
        A: Clone + Iterator,
        B: Default + Eq,
        C: IntoIterator,
        A::Item: Clone,
        C::IntoIter: ExactSizeIterator,
        Object<B, C>: Copy,
    ```

    **NOTE**: This rule is not so strict, and these `where` clauses should be organized in a way that makes most sense but must follow this general rule.

3. Order each entries constraints alphabetically. Here's an example:

    ```rust
    F: 'a + Copy + Trait + FnOnce(T) -> S
    ```

    The ordering should be lifetimes first, then regular traits, then the function traits.


### Magic Numbers

In general, we should avoid magic numbers and constants in general but when they are necessary, they should be declared as such in some module instead of being used in-line with no explanation. Instead of

```text
/// Checks that all the contributions in the round were valid.
pub fn check_all_contributions() -> Result<(), ContributionError> {
    for x in 0..7 {
        check_contribution(x)?;
    }
    Ok(())
}
```

you should use

```rust
/// Contribution Count for the Round-Robin Protocol
pub const PARTICIPANT_COUNT: usize = 7;

/// Checks that all the contributions in the round were valid.
pub fn check_all_contributions() -> Result<(), ContributionError> {
    for x in 0..PARTICIPANT_COUNT {
        check_contribution(x)?;
    }
    Ok(())
}
```

Avoid situations where an arbitrary number needs to be chosen, and if so prefer empirically measured numbers. If for some reason an arbitrary number needs to be chosen, and it should have a known order of magnitude, chose a power of two for the arbitrary number, or something close to a power of two unless the situation calls for something distinctly _not_ a power of two.

### Comments and Documentation

In general, documentation should be added on function/interface boundaries instead of inside code blocks which should be written in a way that explains itself. Sometimes however, we have to do something specific that is counter-intuitive or against some known principle in which case we should comment the code to explain ourselves.

**IMPORTANT**: Documentation should explain _what_ behavior an interface provides, and comments explain _why_ the implementation provides this behavior.

When formatting comments we have a few comment types:

1. `NOTE`: Explains some unintuitive behavior or makes note of some invariants that are being preserved by this particular piece of code.
2. `SAFETY`: Like `NOTE`, except it reflects a safety-critical assumption or invariant and is required for Rust `unsafe` blocks or for some concrete cryptographic code.
3. `TODO`: Like `NOTE`, but involves relaying the information relevant for a fix or future optimization.
4. `FIXME`: Something is critically broken or inconveniently written and should be changed whenever possible.

These four kinds of comments should be formatted as follows:

```rust
#[inline]
fn last(self) -> Option<Self::Item> {
    // NOTE: Although this iterator can never be completed, it has a well-defined final element
    //       "at infinity".
    Some(Default::default())
}
```

The `NOTE` marker and `SAFETY` marker have documentation forms as well but instead are formatted as `# Note` and `# Safety` subsections as follows:

```rust
/// Returns the leaf digests currently stored in the merkle tree.
///
/// # Note
///
/// Since this tree does not start its leaf nodes from the first possible index, indexing into
/// this slice will not be the same as indexing into a slice from a full tree. For all other
/// indexing, use the full indexing scheme.
#[inline]
pub fn leaf_digests(&self) -> &[LeafDigest<C>] {
    &self.leaf_digests
}
```

For documentation headers we also have `# Panics` and `# Errors` as standard headers that describe the conditions under which the function calls `panic` or the error conditions.

Here are some important guidelines to follow for general documentation:

1. All module documentation should exist in the module itself in the header with `//!` doc strings.
2. Be sure to link all documentation that refers to objects in the code.
3. Function documentation should be in present tense. It should answer the question "What does this function do?".
