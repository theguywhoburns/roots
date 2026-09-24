//! The roots node: everything that decides what to do with the library.
//! No part of `roots` builds a `Router` for a caller — that happens here, in
//! exactly one task per node (`node::Node::run`).

pub mod admin;
pub mod config;
pub mod links;
pub mod listen;
pub mod node;
