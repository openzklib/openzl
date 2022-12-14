//! Plonky2 Field Elements

use crate::{bool::Bool, compiler::Compiler};
use core::marker::PhantomData;
use eclair::{
    alloc::{
        mode::{Public, Secret},
        Constant, Variable,
    },
    bool::ConditionalSelect,
    cmp::PartialEq,
    num::{One, Zero},
    ops::{Add, Div, Mul, Neg, Sub},
};
use plonky2::{field::extension::Extendable, hash::hash_types::RichField, iop::target::Target};

/// Boolean Type
pub struct Field<F, const D: usize> {
    /// Target
    pub target: Target,

    /// Type Parameter Marker
    __: PhantomData<F>,
}

impl<F, const D: usize> Field<F, D> {
    /// Builds a new [`Field`] variable from a `target`.
    #[inline]
    pub fn new(target: Target) -> Self {
        Self {
            target,
            __: PhantomData,
        }
    }
}

impl<F, const D: usize> Constant<Compiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    type Type = F;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.builder.constant(*this))
    }
}

impl<F, const D: usize> Variable<Secret, Compiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    type Type = F;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.add_target(*this))
    }

    #[inline]
    fn new_unknown(compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.add_virtual_target())
    }
}

impl<F, const D: usize> Variable<Public, Compiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    type Type = F;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.add_public_target(*this))
    }

    #[inline]
    fn new_unknown(compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.add_virtual_public_target())
    }
}

impl<F, const D: usize> Add<Self, Compiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self, compiler: &mut Compiler<F, D>) -> Self::Output {
        Self::new(compiler.builder.add(self.target, rhs.target))
    }
}

impl<F, const D: usize> Add<F, Compiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    type Output = Self;

    #[inline]
    fn add(self, rhs: F, compiler: &mut Compiler<F, D>) -> Self::Output {
        Self::new(compiler.builder.add_const(self.target, rhs))
    }
}

impl<F, const D: usize> Sub<Self, Compiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self, compiler: &mut Compiler<F, D>) -> Self::Output {
        Self::new(compiler.builder.sub(self.target, rhs.target))
    }
}

impl<F, const D: usize> Mul<Self, Compiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self, compiler: &mut Compiler<F, D>) -> Self::Output {
        Self::new(compiler.builder.mul(self.target, rhs.target))
    }
}

impl<F, const D: usize> Mul<F, Compiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    type Output = Self;

    #[inline]
    fn mul(self, rhs: F, compiler: &mut Compiler<F, D>) -> Self::Output {
        Self::new(compiler.builder.mul_const(rhs, self.target))
    }
}

impl<F, const D: usize> Div<Self, Compiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    type Output = Self;

    #[inline]
    fn div(self, rhs: Self, compiler: &mut Compiler<F, D>) -> Self::Output {
        Self::new(compiler.builder.div(self.target, rhs.target))
    }
}

impl<F, const D: usize> Neg<Compiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    type Output = Self;

    #[inline]
    fn neg(self, compiler: &mut Compiler<F, D>) -> Self::Output {
        Self::new(compiler.builder.neg(self.target))
    }
}

impl<F, const D: usize> PartialEq<Self, Compiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut Compiler<F, D>) -> Bool<F, D> {
        Bool::new(compiler.builder.is_equal(self.target, rhs.target))
    }
}

impl<F, const D: usize> ConditionalSelect<Compiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    #[inline]
    fn select(bit: &Bool<F, D>, lhs: &Self, rhs: &Self, compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.builder.select(bit.target, lhs.target, rhs.target))
    }
}

impl<F, const D: usize> Zero<Compiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    type Verification = Bool<F, D>;

    #[inline]
    fn zero(compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.builder.zero())
    }

    #[inline]
    fn is_zero(&self, compiler: &mut Compiler<F, D>) -> Self::Verification {
        // TODO: is there a better choice here?
        self.eq(&Self::zero(compiler), compiler)
    }
}

impl<F, const D: usize> One<Compiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    type Verification = Bool<F, D>;

    #[inline]
    fn one(compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.builder.one())
    }

    #[inline]
    fn is_one(&self, compiler: &mut Compiler<F, D>) -> Self::Verification {
        // TODO: is there a better choice here?
        self.eq(&Self::one(compiler), compiler)
    }
}
