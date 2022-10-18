//! Overloadable Operations

use core::ops;

/// Defines a unary operation for compilers based on those defined in [`core::ops`].
macro_rules! unary_op {
    ($op:ident, $name:ident, $doc:expr, $doc_op:expr) => {
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
    };
}

/// Defines a binary operation for compilers based on those defined in [`core::ops`].
macro_rules! binary_op {
    ($op:ident, $name:ident, $doc:expr, $doc_op:expr) => {
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
    };
}

/// Defines the assignment variant of a binary operation for compilers based on those defined in
/// [`core::ops`].
macro_rules! binary_op_assign {
    ($op:ident, $name:ident, $doc:expr, $doc_op:expr) => {
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
    };
}

unary_op!(Neg, neg, "Negation", r"\-");
unary_op!(Not, not, "Negation", "!");
binary_op!(Add, add, "Addition", r"\+");
binary_op!(BitAnd, bitand, "Bitwise AND", "&");
binary_op!(BitOr, bitor, "Bitwise OR", "|");
binary_op!(BitXor, bitxor, "Bitwise XOR", "^");
binary_op!(Div, div, "Division", "/");
binary_op!(Mul, mul, "Multiplication", r"\*");
binary_op!(Rem, rem, "Remainder", "%");
binary_op!(Shl, shl, "Left Shift", "<<");
binary_op!(Shr, shr, "Right Shift", ">>");
binary_op!(Sub, sub, "Subtraction", r"\-");
binary_op_assign!(AddAssign, add_assign, "Addition", "+=");
binary_op_assign!(BitAndAssign, bitand_assign, "Bitwise AND", "&=");
binary_op_assign!(BitOrAssign, bitor_assign, "Bitwise OR", "|=");
binary_op_assign!(BitXorAssign, bitxor_assign, "Bitwise XOR", "^=");
binary_op_assign!(DivAssign, div_assign, "Division", "/=");
binary_op_assign!(MulAssign, mul_assign, "Multiplication", "*=");
binary_op_assign!(RemAssign, rem_assign, "Remainder", "%=");
binary_op_assign!(ShlAssign, shl_assign, "Left Shift", "<<=");
binary_op_assign!(ShrAssign, shr_assign, "Right Shift", ">>=");
binary_op_assign!(SubAssign, sub_assign, "Subtraction", "-=");

