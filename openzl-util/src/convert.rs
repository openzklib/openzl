//! Conversion Utilities

use core::convert::Infallible;

/// The Never Type
///
/// This `type` will eventually be replaced by `!`, the primitive never type. See the ongoing
/// discussion for the [never_type #35121](https://github.com/rust-lang/rust/issues/35121) feature.
pub type Never = Infallible;

/// Promotes a [`Never`] value to another type.
#[inline]
pub fn never<T>(_: Never) -> T {
    unreachable!("This type never has any values, so this promotion is safe.")
}

/// Promotes a [`Never`] error value to the `Ok` variant.
#[inline]
pub fn never_err<T>(result: Result<T, Never>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => never(err),
    }
}

/// Structure Field
pub trait Field<T> {
    /// Returns a shared reference to the field value.
    fn get(&self) -> &T;

    /// Returns a mutable reference to the field value.
    fn get_mut(&mut self) -> &mut T;

    /// Converts `self` into the field value, dropping the rest of the structure.
    fn into(self) -> T;
}

/// Enumeration Variant
pub trait Variant<T> {
    /// Constructs the value of the enumeration of the given `variant`.
    fn from(variant: T) -> Self;
}
