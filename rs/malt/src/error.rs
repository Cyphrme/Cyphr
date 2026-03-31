/// Errors produced by DAOLFMT operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Leaf index is out of bounds for the current tree size.
    IndexOutOfBounds {
        /// The requested index.
        index: u64,
        /// The current tree size.
        tree_size: u64,
    },
    /// The requested old size is invalid for a consistency proof.
    InvalidOldSize {
        /// The requested old size.
        old_size: u64,
        /// The current tree size.
        new_size: u64,
    },
    /// The tree is empty.
    EmptyTree,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IndexOutOfBounds { index, tree_size } => {
                write!(
                    f,
                    "leaf index {index} out of bounds for tree of size {tree_size}"
                )
            },
            Error::InvalidOldSize { old_size, new_size } => {
                write!(
                    f,
                    "invalid old size {old_size} for consistency proof against tree of size \
                     {new_size}"
                )
            },
            Error::EmptyTree => write!(f, "operation requires a non-empty tree"),
        }
    }
}

impl std::error::Error for Error {}
