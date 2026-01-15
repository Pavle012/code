//! Authentication flow interface

use reqwest::StatusCode;

use crate::State;
use crate::state::{Credentials, MinecraftLoginFlow};
use crate::util::fetch::REQWEST_CLIENT;
use chrono::{Duration, Utc};
use md5::Md5;
use sha2::Digest;
use uuid::Uuid;
use crate::state::MinecraftProfile;

#[tracing::instrument]
pub async fn check_reachable() -> crate::Result<()> {
    let resp = REQWEST_CLIENT
        .get("https://sessionserver.mojang.com/session/minecraft/hasJoined")
        .send()
        .await?;
    if resp.status() == StatusCode::NO_CONTENT {
        return Ok(());
    }
    resp.error_for_status()?;
    Ok(())
}

#[tracing::instrument]
pub async fn begin_login() -> crate::Result<MinecraftLoginFlow> {
    let state = State::get().await?;

    crate::state::login_begin(&state.pool).await
}

#[tracing::instrument]
pub async fn finish_login(
    code: &str,
    flow: MinecraftLoginFlow,
) -> crate::Result<Credentials> {
    let state = State::get().await?;

    crate::state::login_finish(code, flow, &state.pool).await
}

#[tracing::instrument]
pub async fn get_default_user() -> crate::Result<Option<uuid::Uuid>> {
    let state = State::get().await?;
    let user = Credentials::get_active(&state.pool).await?;
    Ok(user.map(|user| user.offline_profile.id))
}

#[tracing::instrument]
pub async fn set_default_user(user: uuid::Uuid) -> crate::Result<()> {
    let state = State::get().await?;
    let users = Credentials::get_all(&state.pool).await?;
    let (_, mut user) = users.remove(&user).ok_or_else(|| {
        crate::ErrorKind::OtherError(format!(
            "Tried to get nonexistent user with ID {user}"
        ))
        .as_error()
    })?;

    user.active = true;
    user.upsert(&state.pool).await?;

    Ok(())
}

/// Remove a user account from the database
#[tracing::instrument]
pub async fn remove_user(uuid: uuid::Uuid) -> crate::Result<()> {
    let state = State::get().await?;

    let users = Credentials::get_all(&state.pool).await?;

    if let Some((uuid, user)) = users.remove(&uuid) {
        Credentials::remove(uuid, &state.pool).await?;

        if user.active
            && let Some((_, mut user)) = users.into_iter().next()
        {
            user.active = true;
            user.upsert(&state.pool).await?;
        }
    }

    Ok(())
}

/// Get a copy of the list of all user credentials
#[tracing::instrument]
pub async fn users() -> crate::Result<Vec<Credentials>> {
    let state = State::get().await?;
    let users = Credentials::get_all(&state.pool).await?;
    Ok(users.into_iter().map(|x| x.1).collect())
}

#[tracing::instrument]
pub async fn offline_login(
    username: String,
) -> crate::Result<Credentials> {
    let state = State::get().await?;
    let mut hasher = Md5::new();
    hasher.update(format!("OfflinePlayer:{}", username).as_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);

    // UUID v3/v5 version and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x30; // Version 3 (MD5 based)
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant 1 (RFC 4122)

    let uuid = Uuid::from_bytes(bytes);

    let credentials = Credentials {
        offline_profile: MinecraftProfile {
            id: uuid,
            name: username,
            skins: vec![],
            capes: vec![],
        },
        access_token: "offline_token".to_string(), // Dummy token
        refresh_token: "offline_refresh".to_string(), // Dummy token
        expires: Utc::now() + Duration::days(365 * 100), // Effectively never expires
        active: true,
    };

    credentials.upsert(&state.pool).await?;

    Ok(credentials)
}
