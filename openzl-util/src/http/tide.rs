// Copyright 2019-2022 Manta Network.
// This file is part of manta-rs.
//
// manta-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

//! Tide HTTP Server Utilities

use crate::serde::{de::DeserializeOwned, Serialize};
use core::future::Future;

pub use tide::{listener, Body, Error, Request, Response, Server, StatusCode};

/// Generates the JSON body for the output of `f`, returning an HTTP reponse.
#[inline]
pub async fn into_body<R, E, F, Fut>(f: F) -> Result<Response, Error>
where
    R: Serialize,
    E: Into<Error>,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<R, E>>,
{
    Ok(Body::from_json(&f().await.map_err(Into::into)?)?.into())
}

/// Executes `f` on the incoming `request`.
#[inline]
pub async fn execute<S, T, R, E, F, Fut>(mut request: Request<S>, f: F) -> Result<Response, Error>
where
    S: Clone,
    T: DeserializeOwned,
    R: Serialize,
    E: Into<Error>,
    F: FnOnce(S, T) -> Fut,
    Fut: Future<Output = Result<R, E>>,
{
    let args = request.body_json::<T>().await?;
    into_body(move || async move { f(request.state().clone(), args).await }).await
}

/// Registers a `POST` command with the given `path` and execution `f`.
#[inline]
pub fn register_post<S, T, R, E, F, Fut>(api: &mut Server<S>, path: &'static str, f: F)
where
    S: Clone + Send + Sync + 'static,
    T: DeserializeOwned + Send + 'static,
    R: Serialize + 'static,
    E: Into<Error> + 'static,
    F: Clone + Send + Sync + 'static + Fn(S, T) -> Fut,
    Fut: Future<Output = Result<R, E>> + Send + 'static,
{
    api.at(path).post(move |r| execute(r, f.clone()));
}
