//! Response envelope + pagination helpers shared by every handler.

use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: T,
}

impl<T> ApiResponse<T> {
    pub fn new(data: T) -> Self {
        ApiResponse {
            success: true,
            data,
        }
    }
}

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

pub fn ok<T: Serialize>(data: T) -> ApiResponse<T> {
    ApiResponse::new(data)
}

pub fn created<T: Serialize>(data: T) -> (StatusCode, ApiResponse<T>) {
    (StatusCode::CREATED, ApiResponse::new(data))
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MessageResponse {
    pub message: String,
}

pub fn message(text: impl Into<String>) -> MessageResponse {
    MessageResponse {
        message: text.into(),
    }
}

/// Generic page of results with the metadata a client needs to paginate.
#[derive(Debug, Serialize, ToSchema)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub page: u32,
    pub per_page: u32,
    pub total: i64,
    pub total_pages: u32,
    pub has_next: bool,
    pub has_prev: bool,
}

impl<T> Page<T> {
    pub fn new(items: Vec<T>, page: u32, per_page: u32, total: i64) -> Self {
        let per_page = per_page.max(1);
        let total_pages = if total <= 0 {
            0
        } else {
            (total as u64).div_ceil(per_page as u64) as u32
        };
        Page {
            items,
            page,
            per_page,
            total,
            total_pages,
            has_next: page < total_pages,
            has_prev: page > 1,
        }
    }
}
