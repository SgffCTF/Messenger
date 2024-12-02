use actix_web::{ web, App, HttpServer };
use actix_session::{ SessionMiddleware, storage::CookieSessionStore };
use dotenv::dotenv;

mod db;
mod models;
mod schema;
mod handlers;
mod utils;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let start_server = chrono::Utc::now().timestamp() as u64;

    let pool = db::establish_connection();
    println!("Server started at https://0.0.0.0:8080");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(start_server.clone()))
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    utils::generate_session_key(start_server)
                )
                    .cookie_content_security(actix_session::config::CookieContentSecurity::Signed)
                    .cookie_secure(false)
                    .build()
            )
            .route("/register", web::post().to(handlers::register_user))
            .route("/login", web::post().to(handlers::login_user))
            .route("/users", web::get().to(handlers::get_users))
            .route("/start_convo", web::post().to(handlers::start_convo))
            .route("/convos", web::get().to(handlers::get_convos))
            .route("/convo/{convo_id}", web::post().to(handlers::send_message))
            .route("/convo/{convo_id}", web::get().to(handlers::get_messages))
            .route("/health", web::get().to(handlers::health))
    })
        .bind("0.0.0.0:8080")?
        .run().await
}
