use actix_web::{ web, App, HttpServer, Responder };
use actix_files as fs;
use actix_session::{ SessionMiddleware, storage::CookieSessionStore };
use actix_cors::Cors;
use dotenv::dotenv;

mod db;
mod models;
mod schema;
mod handlers;
mod utils;

pub async fn login_form() -> impl Responder {
    fs::NamedFile::open("./static/login.html").unwrap()
}

pub async fn register_form() -> impl Responder {
    fs::NamedFile::open("./static/register.html").unwrap()
}

pub async fn dashboard() -> impl Responder {
    fs::NamedFile::open("./static/dashboard.html").unwrap()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let start_server = chrono::Utc::now().timestamp() as u64;

    let pool = db::establish_connection();
    println!("Server started at http://0.0.0.0:8080!");
    HttpServer::new(move || {
        let cors = Cors::permissive();

        let session = SessionMiddleware::builder(
            CookieSessionStore::default(),
            utils::generate_session_key(start_server)
        )
            .cookie_content_security(actix_session::config::CookieContentSecurity::Signed)
            .cookie_secure(false)
            .build();

        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(start_server.clone()))
            .wrap(session)
            .wrap(cors)
            .service(fs::Files::new("/static", "./static").show_files_listing())
            .route("/register", web::post().to(handlers::register_user))
            .route("/register", web::get().to(register_form))
            .route("/login", web::post().to(handlers::login_user))
            .route("login", web::get().to(login_form))
            .route("/users", web::get().to(handlers::get_users))
            .route("/current_user", web::get().to(handlers::current_user_id))
            .route("/start_convo", web::post().to(handlers::start_convo))
            .route("/convos", web::get().to(handlers::get_convos))
            .route("/convo/{convo_id}", web::post().to(handlers::send_message))
            .route("/convo/{convo_id}", web::get().to(handlers::get_messages))
            .route("/health", web::get().to(handlers::health))
            .route("/backup/{convo_id}", web::post().to(handlers::backup_convo))
            .route("/backup/{hash}.zip", web::get().to(handlers::download_backup))
            .route("dashboard", web::get().to(dashboard))
    })
        .bind("0.0.0.0:8080")?
        .run().await
}
