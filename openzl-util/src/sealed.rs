//! Sealed Traits

/// Creates a new `sealed::Sealed` trait in the current module.
#[macro_export]
macro_rules! create_seal {
    () => {
        /// Sealed Trait Module
        mod sealed {
            /// Sealed Trait
            pub trait Sealed {}
        }
    };
}

/// Adds a `sealed::Sealed` implementation to `$type`.
#[macro_export]
macro_rules! seal {
    ($($type:tt),+ $(,)?) => {
        $(impl sealed::Sealed for $type {})+
    };
}
