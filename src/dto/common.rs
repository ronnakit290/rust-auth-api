//! Pagination and shared query helpers.

use serde::Deserialize;
use utoipa::ToSchema;

pub const DEFAULT_PER_PAGE: u32 = 20;
pub const MAX_PER_PAGE: u32 = 100;

#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct PaginationQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

impl PaginationQuery {
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(1).max(1)
    }

    pub fn per_page(&self) -> u32 {
        self.per_page
            .unwrap_or(DEFAULT_PER_PAGE)
            .clamp(1, MAX_PER_PAGE)
    }

    pub fn limit(&self) -> i64 {
        self.per_page() as i64
    }

    pub fn offset(&self) -> i64 {
        ((self.page() - 1) as i64) * self.per_page() as i64
    }
}
