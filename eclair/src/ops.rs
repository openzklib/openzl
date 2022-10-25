//! Overloadable Operations

use core::ops;

/// Defines a unary operation for compilers based on those defined in [`core::ops`].
macro_rules! unary_op {
    ($op:ident, $has_op:ident, $name:ident, $doc:expr, $doc_op:expr) => {
        #[doc = $doc]
        #[doc = " with the `"]
        #[doc = $doc_op]
        #[doc = "` Operator"]
        pub trait $op<COM = ()>
        where
            COM: ?Sized,
        {
            /// Output Type
            #[doc = "The resulting type after applying the `"]
            #[doc = $doc_op]
            #[doc = "` operator."]
            type Output;

            #[doc = "Performs the `"]
            #[doc = $doc_op]
            #[doc = "self` operation."]
            fn $name(self, compiler: &mut COM) -> Self::Output;
        }

        impl<T> $op for T
        where
            T: ops::$op,
        {
            type Output = T::Output;

            #[inline]
            fn $name(self, _: &mut ()) -> Self::Output {
                self.$name()
            }
        }

        #[doc = "Compiler Reflection for "]
        #[doc = $doc]
        #[doc = " with the `"]
        #[doc = $doc_op]
        #[doc = "` Operator"]
        pub trait $has_op<T> {
            /// Output Type
            #[doc = "The resulting type after applying the `"]
            #[doc = $doc_op]
            #[doc = "` operator."]
            type Output;

            #[doc = "Performs the `"]
            #[doc = $doc_op]
            #[doc = "t` operation over the `self` compiler."]
            fn $name(&mut self, t: T) -> Self::Output;
        }

        impl<COM, T> $has_op<T> for COM
        where
            T: $op<COM>,
        {
            type Output = T::Output;

            #[inline]
            fn $name(&mut self, t: T) -> Self::Output {
                t.$name(self)
            }
        }
    };
}

/// Defines a binary operation for compilers based on those defined in [`core::ops`].
macro_rules! binary_op {
    ($op:ident, $has_op:ident, $name:ident, $doc:expr, $doc_op:expr) => {
        #[doc = $doc]
        #[doc = " with the `"]
        #[doc = $doc_op]
        #[doc = "` Operator"]
        pub trait $op<Rhs = Self, COM = ()>
        where
            COM: ?Sized,
        {
            #[doc = "The resulting type after applying the `"]
            #[doc = $doc_op]
            #[doc = "` operator."]
            type Output;

            #[doc = "Performs the `self"]
            #[doc = $doc_op]
            #[doc = " rhs` operation."]
            fn $name(self, rhs: Rhs, compiler: &mut COM) -> Self::Output;
        }

        impl<T, Rhs> $op<Rhs> for T
        where
            T: ops::$op<Rhs>,
        {
            type Output = T::Output;

            #[inline]
            fn $name(self, rhs: Rhs, _: &mut ()) -> Self::Output {
                self.$name(rhs)
            }
        }

        #[doc = "Compiler Reflection for "]
        #[doc = $doc]
        #[doc = " with the `"]
        #[doc = $doc_op]
        #[doc = "` Operator"]
        pub trait $has_op<L, R = L> {
            /// Output Type
            #[doc = "The resulting type after applying the `"]
            #[doc = $doc_op]
            #[doc = "` operator."]
            type Output;

            #[doc = "Performs the `lhs"]
            #[doc = $doc_op]
            #[doc = "rhs` operation over the `self` compiler."]
            fn $name(&mut self, lhs: L, rhs: R) -> Self::Output;
        }

        impl<COM, L, R> $has_op<L, R> for COM
        where
            L: $op<R, COM>,
        {
            type Output = L::Output;

            #[inline]
            fn $name(&mut self, lhs: L, rhs: R) -> Self::Output {
                lhs.$name(rhs, self)
            }
        }
    };
}

/// Defines the assignment variant of a binary operation for compilers based on those defined in
/// [`core::ops`].
macro_rules! binary_op_assign {
    ($op:ident, $has_op:ident, $name:ident, $doc:expr, $doc_op:expr) => {
        #[doc = "Assigned "]
        #[doc = $doc]
        #[doc = " with the `"]
        #[doc = $doc_op]
        #[doc = "` Operator"]
        pub trait $op<Rhs = Self, COM = ()>
        where
            COM: ?Sized,
        {
            #[doc = "Performs the `self"]
            #[doc = $doc_op]
            #[doc = "rhs` operation."]
            fn $name(&mut self, rhs: Rhs, compiler: &mut COM);
        }

        impl<T, Rhs> $op<Rhs> for T
        where
            T: ops::$op<Rhs>,
        {
            #[inline]
            fn $name(&mut self, rhs: Rhs, _: &mut ()) {
                self.$name(rhs)
            }
        }

        #[doc = "Compiler Reflection for Assigning"]
        #[doc = $doc]
        #[doc = " with the `"]
        #[doc = $doc_op]
        #[doc = "` Operator"]
        pub trait $has_op<L, R = L> {
            #[doc = "Performs the `lhs"]
            #[doc = $doc_op]
            #[doc = "rhs` operation over the `self` compiler."]
            fn $name(&mut self, lhs: &mut L, rhs: R);
        }

        impl<COM, L, R> $has_op<L, R> for COM
        where
            L: $op<R, COM>,
        {
            #[inline]
            fn $name(&mut self, lhs: &mut L, rhs: R) {
                lhs.$name(rhs, self)
            }
        }
    };
}

unary_op!(Neg, HasNeg, neg, "Negation", r"\-");
unary_op!(Not, HasNot, not, "Negation", "!");
binary_op!(Add, HasAdd, add, "Addition", r"\+");
binary_op!(BitAnd, HasBitAnd, bitand, "Bitwise AND", "&");
binary_op!(BitOr, HasBitOr, bitor, "Bitwise OR", "|");
binary_op!(BitXor, HasBitXor, bitxor, "Bitwise XOR", "^");
binary_op!(Div, HasDiv, div, "Division", "/");
binary_op!(Mul, HasMul, mul, "Multiplication", r"\*");
binary_op!(Rem, HasRem, rem, "Remainder", "%");
binary_op!(Shl, HasShl, shl, "Left Shift", "<<");
binary_op!(Shr, HasShr, shr, "Right Shift", ">>");
binary_op!(Sub, HasSub, sub, "Subtraction", r"\-");
binary_op_assign!(AddAssign, HasAddAssign, add_assign, "Addition", "+=");
binary_op_assign!(
    BitAndAssign,
    HasBitAndAssign,
    bitand_assign,
    "Bitwise AND",
    "&="
);
binary_op_assign!(
    BitOrAssign,
    HasBitOrAssign,
    bitor_assign,
    "Bitwise OR",
    "|="
);
binary_op_assign!(
    BitXorAssign,
    HasBitXorAssign,
    bitxor_assign,
    "Bitwise XOR",
    "^="
);
binary_op_assign!(DivAssign, HasDivAssign, div_assign, "Division", "/=");
binary_op_assign!(MulAssign, HasMulAssign, mul_assign, "Multiplication", "*=");
binary_op_assign!(RemAssign, HasRemAssign, rem_assign, "Remainder", "%=");
binary_op_assign!(ShlAssign, HasShlAssign, shl_assign, "Left Shift", "<<=");
binary_op_assign!(ShrAssign, HasShrAssign, shr_assign, "Right Shift", ">>=");
binary_op_assign!(SubAssign, HasSubAssign, sub_assign, "Subtraction", "-=");
