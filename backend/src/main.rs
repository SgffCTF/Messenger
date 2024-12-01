use actix_web::{ web, App, HttpServer };
use actix_session::{ SessionMiddleware, storage::CookieSessionStore };
use actix_web::cookie::Key;
use dotenv::dotenv;

mod db;
mod models;
mod schema;
mod handlers;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let session_key = Key::generate();

    let pool = db::establish_connection();
    println!("Server started at https://0.0.0.0:8080");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), session_key.clone())
                    .cookie_content_security(actix_session::config::CookieContentSecurity::Private)
                    .cookie_secure(false)
                    .build()
            )
            .route("/register", web::post().to(handlers::register_user))
            .route("/login", web::post().to(handlers::login_user))
            .route("/users", web::get().to(handlers::get_users))
            .route("/start_convo", web::post().to(handlers::start_convo))
            .route(
                "/health",
                web::get().to(|| async { "Healthy" })
            )
    })
        .bind("0.0.0.0:8080")?
        .run().await
}
