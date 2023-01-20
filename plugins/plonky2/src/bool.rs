//! Plonky2 Booleans

use crate::compiler::Compiler;
use core::marker::PhantomData;
use eclair::{
    alloc::{
        mode::{Public, Secret},
        Constant, Variable,
    },
    bool::Assert,
    cmp::PartialEq,
    ops::{BitAnd, Not},
    Has,
};
use plonky2::{field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget};

/// Boolean Type
pub struct Bool<F, const D: usize> {
    /// Target
    pub target: BoolTarget,

    /// Type Parameter Marker
    __: PhantomData<F>,
}

impl<F, const D: usize> Bool<F, D> {
    /// Builds a new [`Bool`] variable from a `target`.
    #[inline]
    pub fn new(target: BoolTarget) -> Self {
        Self {
            target,
            __: PhantomData,
        }
    }
}

impl<F, const D: usize> Has<bool> for Compiler<F, D>
where
    F: RichField + Extendable<D>,
{
    type Type = Bool<F, D>;
}

impl<F, const D: usize> Assert for Compiler<F, D>
where
    F: RichField + Extendable<D>,
{
    #[inline]
    fn assert(&mut self, b: &Bool<F, D>) {
        self.builder.assert_bool(b.target)
    }
}

impl<F, const D: usize> Constant<Compiler<F, D>> for Bool<F, D>
where
    F: RichField + Extendable<D>,
{
    type Type = bool;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.builder.constant_bool(*this))
    }
}

impl<F, const D: usize> Variable<Secret, Compiler<F, D>> for Bool<F, D>
where
    F: RichField + Extendable<D>,
{
    type Type = bool;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.add_bool_target(*this))
    }

    #[inline]
    fn new_unknown(compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.add_virtual_bool_target())
    }
}

impl<F, const D: usize> Variable<Public, Compiler<F, D>> for Bool<F, D>
where
    F: RichField + Extendable<D>,
{
    type Type = bool;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.add_public_bool_target(*this))
    }

    #[inline]
    fn new_unknown(compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.add_virtual_public_bool_target())
    }
}

impl<F, const D: usize> BitAnd<Self, Compiler<F, D>> for Bool<F, D>
where
    F: RichField + Extendable<D>,
{
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self, compiler: &mut Compiler<F, D>) -> Self::Output {
        Self::new(compiler.builder.and(self.target, rhs.target))
    }
}

impl<F, const D: usize> Not<Compiler<F, D>> for Bool<F, D>
where
    F: RichField + Extendable<D>,
{
    type Output = Self;

    #[inline]
    fn not(self, compiler: &mut Compiler<F, D>) -> Self::Output {
        Self::new(compiler.builder.not(self.target))
    }
}

impl<F, const D: usize> PartialEq<Self, Compiler<F, D>> for Bool<F, D>
where
    F: RichField + Extendable<D>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut Compiler<F, D>) -> Self {
        Bool::new(
            compiler
                .builder
                .is_equal(self.target.target, rhs.target.target),
        )
    }
}
