//! Native MongoDB 6.0+ adapter implementing all stores.

pub mod indexes;
pub mod models;

pub use indexes::ensure_indexes;
pub use models::*;

/// MongoDB database store adapter.
#[derive(Debug, Clone)]
pub struct MongoStore;
