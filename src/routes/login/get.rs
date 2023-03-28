use axum::http::Response;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_flash::IncomingFlashes;
use std::fmt::Write;

pub async fn login_form(flash_messages: IncomingFlashes) -> impl IntoResponse {
    let mut error_html = String::new();
    for m in flash_messages.iter() {
        writeln!(error_html, "<p><i>{}</i></p>", m.1).unwrap();
    }

    (
        flash_messages,
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(format!(
                r#"<!DOCTYPE html>
<html lang="en">

<head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8">
    <title>Login</title>
</head>

<body>
    {error_html}
    <form action="/login" method="post">
        <label>Username
            <input type="text" placeholder="Enter Username" name="username">
        </label>
        <label>Password
            <input type="password" placeholder="Enter Password" name="password">
        </label>
        <button type="submit">Login</button>
    </form>
</body>

</html>
                "#,
            ))
            .unwrap(),
    )
}
