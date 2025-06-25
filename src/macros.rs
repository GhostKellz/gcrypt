//! Internal macros for the gcrypt library.

/// Create a constant-time conditional assignment macro
macro_rules! conditional_assign {
    ($lhs:expr, $rhs:expr, $condition:expr) => {
        $lhs.conditional_assign(&$rhs, $condition);
    };
}

/// Create a conditional selection macro
macro_rules! conditional_select {
    ($a:expr, $b:expr, $condition:expr) => {
        subtle::ConditionallySelectable::conditional_select(&$a, &$b, $condition)
    };
}

/// Assert that two expressions are equal in constant time
macro_rules! ct_assert_eq {
    ($left:expr, $right:expr) => {
        debug_assert!(bool::from(subtle::ConstantTimeEq::ct_eq(&$left, &$right)));
    };
}

/// Generate documentation for curve parameters
macro_rules! curve_doc {
    ($curve:expr, $description:expr) => {
        concat!(
            "Implementation for ",
            $curve,
            ".\n\n",
            $description,
            "\n\nThis implementation uses modern Rust features and constant-time operations."
        )
    };
}

/// Create a feature-gated function
macro_rules! feature_fn {
    (
        $(#[$attr:meta])*
        $vis:vis fn $name:ident$(<$($generics:tt)*>)?($($args:tt)*) $(-> $ret:ty)? 
        where $feature:literal 
        $body:block
    ) => {
        #[cfg(feature = $feature)]
        $(#[$attr])*
        $vis fn $name$(<$($generics)*>)?($($args)*) $(-> $ret)? $body
    };
}

pub(crate) use {conditional_assign, conditional_select, ct_assert_eq, curve_doc, feature_fn};
