use axum::response::{ErrorResponse, IntoResponse, Redirect, Response};
use axum_flash::IncomingFlashes;
use hyper::StatusCode;
use std::fmt::Write;

use crate::session_state::TypedSession;

pub async fn change_password_form(
    session: TypedSession,
    flash_messages: IncomingFlashes,
) -> Result<Response, ErrorResponse> {
    let user_id = session.get_user_id().await;
    if user_id.is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let mut msg_html = String::new();
    for m in flash_messages.iter() {
        writeln!(msg_html, "<p><i>{}</i></p>", m.1).unwrap();
    }

    Ok((
        flash_messages,
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(format!(
                r#"<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8">
    <title>Change Password</title>
    </head>
    <body>
    {msg_html}
    <form action="/admin/password" method="post">
    <label>Current password
    <input
    type="password"
    placeholder="Enter current password"
    name="current_password"
    >
    </label>
    <br>
    <label>New password
    <input
    type="password"
    placeholder="Enter new password"
    name="new_password"
    >
    </label>
    <br>
    <label>Confirm new password
    <input
    type="password"
    placeholder="Type the new password again"
    name="new_password_check"
    >
    </label>
    <br>
    <button type="submit">Change password</button>
    </form>
    <p><a href="/admin/dashboard">&lt;- Back</a></p>
    </body>
</html>"#
            ))
            .unwrap(),
    )
        .into_response())
}
