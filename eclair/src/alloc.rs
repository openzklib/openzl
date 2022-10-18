//! Compiler Allocation
//!
//! When building programs, we may need to transfer values across compilers, say from a native
//! compiler into a circuit-building compiler. This lifting of values into another compiler is known
//! as "allocation". The two `trait`s responsible for this allocation scheme are [`Constant`] and
//! [`Variable`]. See their documentation for more.
//!
//! # Note on Terminology
//!
//! Allocation does not necessarily refer to allocation of memory nor the simulation of memory-based
//! abstractions inside of compilers, like heap allocation. Allocation only refers to lifting
//! constants and variables from one compiler to another.

use core::marker::PhantomData;

#[cfg(feature = "alloc")]
use {
    openzl_util::{into_array_unchecked, iter, Array, BoxArray},
    rust_alloc::{boxed::Box, vec::Vec},
};

/// Constant Type Alias
pub type Const<C, COM> = <C as Constant<COM>>::Type;

/// Compiler Constant
///
/// A compiler [`Constant`] is a kind of allocated value that **must** be known at
/// _compilation time_. In this case, we take an explicit value of the underlying type and directly
/// return an allocated value in the `COM` compiler. Contrast this with [`Variable`] types whose
/// values are not known at _compilation time_ and are only known at _execution time_.
pub trait Constant<COM = ()>
where
    COM: ?Sized,
{
    /// Underlying Type
    type Type;

    /// Allocates a new constant from `this` into the `compiler`.
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self;
}

impl Constant for bool {
    type Type = bool;

    #[inline]
    fn new_constant(this: &Self::Type, _: &mut ()) -> Self {
        *this
    }
}

impl<COM> Constant<COM> for ()
where
    COM: ?Sized,
{
    type Type = ();

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
    }
}

impl<T, COM> Constant<COM> for PhantomData<T>
where
    COM: ?Sized,
{
    type Type = PhantomData<T>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        PhantomData
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl<T, const N: usize, COM> Constant<COM> for [T; N]
where
    COM: ?Sized,
    T: Constant<COM>,
{
    type Type = [T::Type; N];

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        into_array_unchecked(
            this.iter()
                .map(|this| this.as_constant(compiler))
                .collect::<Vec<_>>(),
        )
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl<T, COM> Constant<COM> for Vec<T>
where
    COM: ?Sized,
    T: Constant<COM>,
{
    type Type = Vec<T::Type>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        this.iter().map(|this| this.as_constant(compiler)).collect()
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl<T, COM> Constant<COM> for Box<[T]>
where
    COM: ?Sized,
    T: Constant<COM>,
{
    type Type = Box<[T::Type]>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        this.iter().map(|this| this.as_constant(compiler)).collect()
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl<T, const N: usize, COM> Constant<COM> for Array<T, N>
where
    COM: ?Sized,
    T: Constant<COM>,
{
    type Type = Array<T::Type, N>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        this.iter().map(|this| this.as_constant(compiler)).collect()
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl<T, const N: usize, COM> Constant<COM> for BoxArray<T, N>
where
    COM: ?Sized,
    T: Constant<COM>,
{
    type Type = Array<T::Type, N>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        this.iter().map(|this| this.as_constant(compiler)).collect()
    }
}

/// Variable Type Alias
pub type Var<V, M, COM> = <V as Variable<M, COM>>::Type;

/// Compiler Variable
///
/// A compiler [`Variable`] is a kind of allocated value that **cannot** have a known value at
/// _compilation time_ but _does_ have one at _execution time_. In this case, we require two
/// allocation methods [`new_unknown`](Self::new_unknown) and [`new_known`](Self::new_known) in
/// order to use the variables in `COM` during both the compilation and execution phases. Contrast
/// this with [`Constant`] types whose values must be known at _compilation time_.
///
/// # Allocation Modes
///
/// The tag `M` in the type parameters of this trait refers to the [`Variable`]'s allocation mode.
/// See the [`mode`] module for more details on why allocation modes are necessary and useful and
/// how to use them.
pub trait Variable<M, COM = ()>
where
    COM: ?Sized,
{
    /// Underlying Type
    type Type;

    /// Allocates a new unknown value into the `compiler`. The terminology "unknown" refers to the
    /// fact that we need to allocate a slot for this variable during compilation time, but do not
    /// yet know its underlying value.
    fn new_unknown(compiler: &mut COM) -> Self;

    /// Allocates a new known value from `this` into the `compiler`. The terminology "known" refers
    /// to the fact that we have access to the underyling value during execution time where we are
    /// able to use its concrete value for execution.
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self;
}

impl<M, COM> Variable<M, COM> for ()
where
    COM: ?Sized,
{
    type Type = ();

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        let _ = compiler;
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
    }
}

impl<T, M, COM> Variable<M, COM> for PhantomData<T>
where
    COM: ?Sized,
{
    type Type = PhantomData<T>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        let _ = compiler;
        PhantomData
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        PhantomData
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl<T, M, COM> Variable<M, COM> for Box<T>
where
    COM: ?Sized,
    T: Variable<M, COM>,
{
    type Type = Box<T::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(T::new_known(this, compiler))
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl<T, const N: usize, M, COM> Variable<M, COM> for [T; N]
where
    COM: ?Sized,
    T: Variable<M, COM>,
{
    type Type = [T::Type; N];

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        into_array_unchecked(
            iter::repeat_with(|| compiler.allocate_unknown())
                .take(N)
                .collect::<Vec<_>>(),
        )
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        into_array_unchecked(
            this.iter()
                .map(|this| this.as_known(compiler))
                .collect::<Vec<_>>(),
        )
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl<T, const N: usize, M, COM> Variable<M, COM> for Array<T, N>
where
    COM: ?Sized,
    T: Variable<M, COM>,
{
    type Type = Array<T::Type, N>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        iter::repeat_with(|| compiler.allocate_unknown())
            .take(N)
            .collect()
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        this.iter().map(|this| this.as_known(compiler)).collect()
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl<T, const N: usize, M, COM> Variable<M, COM> for BoxArray<T, N>
where
    COM: ?Sized,
    T: Variable<M, COM>,
{
    type Type = BoxArray<T::Type, N>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        iter::repeat_with(|| compiler.allocate_unknown())
            .take(N)
            .collect()
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        this.iter().map(|this| this.as_known(compiler)).collect()
    }
}

/// Allocation Auto-`trait`
///
/// Allocation schemes are built up from the individual variables which can be allocated into a
/// given compiler. This `trait` is automatically implemented to give allocate-able values access to
/// generic methods that perform allocation into any compiler whenever the associated allocation
/// scheme allows it.
///
/// See [`Constant`] and [`Variable`] for more details on including a specific variable in the
/// allocation scheme for a compiler.
pub trait Allocate<COM = ()>
where
    COM: ?Sized,
{
    /// Allocates `self` as a constant in `compiler`. See [`C::new_constant`] for more.
    ///
    /// [`C::new_constant`]: Constant::new_constant
    #[inline]
    fn as_constant<C>(&self, compiler: &mut COM) -> C
    where
        C: Constant<COM, Type = Self>,
    {
        C::new_constant(self, compiler)
    }

    /// Allocates an unknown value of type `Self` into `compiler`. See [`V::new_unknown`] for more.
    ///
    /// [`V::new_unknown`]: Variable::new_unknown
    #[inline]
    fn as_unknown<M, V>(compiler: &mut COM) -> V
    where
        V: Variable<M, COM, Type = Self>,
    {
        V::new_unknown(compiler)
    }

    /// Allocates `self` as a known value in `compiler`. See [`V::new_known`] for more.
    ///
    /// [`V::new_known`]: Variable::new_known
    #[inline]
    fn as_known<M, V>(&self, compiler: &mut COM) -> V
    where
        V: Variable<M, COM, Type = Self>,
    {
        V::new_known(self, compiler)
    }
}

impl<COM, T> Allocate<COM> for T
where
    COM: ?Sized,
    T: ?Sized,
{
}

/// Allocator Auto-`trait`
///
/// Allocation schemes are built up from the individual variables which can be allocated into a
/// given compiler. This `trait` is automatically implemented to give compilers access to generic
/// methods that perform allocation over any variables defined over them.
///
/// See [`Constant`] and [`Variable`] for more details on including a specific variable in the
/// allocation scheme for a compiler.
pub trait Allocator {
    /// Allocates a constant with the given `value` into `self`. See [`C::new_constant`] for more.
    ///
    /// [`C::new_constant`]: Constant::new_constant
    #[inline]
    fn allocate_constant<C>(&mut self, value: &C::Type) -> C
    where
        C: Constant<Self>,
    {
        C::new_constant(value, self)
    }

    /// Allocates an unknown variable into `self`. See [`V::new_unknown`] for more.
    ///
    /// [`V::new_unknown`]: Variable::new_unknown
    #[inline]
    fn allocate_unknown<M, V>(&mut self) -> V
    where
        V: Variable<M, Self>,
    {
        V::new_unknown(self)
    }

    /// Allocates a known variable with the given `value` into `self`. See [`V::new_known`] for
    /// more.
    ///
    /// [`V::new_known`]: Variable::new_known
    #[inline]
    fn allocate_known<M, V>(&mut self, value: &V::Type) -> V
    where
        V: Variable<M, Self>,
    {
        V::new_known(value, self)
    }
}

impl<COM> Allocator for COM where COM: ?Sized {}

/// Allocation Modes for [`Variable`] Types
///
/// When allocating objects of type [`Variable`], we can attach an explicit mode tag to inform the
/// compiler that the variable will have some custom allocation semantics. Below we define some
/// useful canonical modes [`Derived`], [`Constant`], [`Public`], and [`Secret`]. The latter two
/// modes are most useful for zero-knowledge [`ProofSystem`]-based execution engines where we want
/// to distinguish between _secret witness_ variables and _public input_ variables.
///
/// [`Derived`]: mode::Derived
/// [`Constant`]: mode::Constant
/// [`Public`]: mode::Public
/// [`Secret`]: mode::Secret
/// [`ProofSystem`]: crate::execution::ProofSystem
pub mod mode {
    use super::*;

    /// Generic Derived Allocation Mode
    ///
    /// Whenever a variable has internal structure that employs different allocation modes for
    /// different internal variables, it should be marked with this allocation mode.
    ///
    /// # Optional Type Annotations
    ///
    /// To ensure that all types are constrained when implementing [`Variable`], we can provide
    /// optional types to [`Derived`]. See [E0207](https://doc.rust-lang.org/error-index.html#E0207)
    /// for more on unconstrained type errors.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Derived<T = ()>(PhantomData<T>);

    /// Constant Allocation Mode
    ///
    /// In some cases, compilers may not be able to adapt under the [`Constant`]-[`Variable`]
    /// distinction and may need to use [`Variable`] for all of their allocation. In those cases,
    /// this allocation mode may be useful to add some leakage to the [`Variable`] abstraction. This
    /// marker can also be used in situations where a canonical name is needed to refer to
    /// constants.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Constant;

    /// Public Allocation Mode
    ///
    /// Whenever a variable's underlying value **must** be publicly revealed during execution, it
    /// should be marked with this allocation mode.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Public;

    impl<T> From<Derived<T>> for Public {
        #[inline]
        fn from(d: Derived<T>) -> Self {
            let _ = d;
            Self
        }
    }

    /// Secret Allocation Mode
    ///
    /// Whenever a variable's underlying value **must not** be publicly revealed during execution,
    /// it should be marked with this allocation mode.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Secret;

    impl<T> From<Derived<T>> for Secret {
        #[inline]
        fn from(d: Derived<T>) -> Self {
            let _ = d;
            Self
        }
    }
}
