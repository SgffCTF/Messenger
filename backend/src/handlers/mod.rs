use diesel::prelude::*;
use actix_web::{ web, HttpResponse };
use actix_session::Session;
use bcrypt::{ hash, DEFAULT_COST };
use bcrypt::verify;
use crate::{ db::DbPool, models::User };
use crate::schema::users::{ self, tag, nickname, last_seen };
use crate::models::{ DisplayUserData, LoginData, NewUser, RegisterData };
use chrono::Utc;

pub async fn register_user(
    pool: web::Data<DbPool>,
    user_data: web::Json<RegisterData>
) -> HttpResponse {
    let mut conn = pool.get().unwrap();

    // Хешируем пароль
    let hashed_password = match hash(&user_data.password, DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Password hashing failed");
        }
    };

    // Создаем нового пользователя
    let new_user = NewUser {
        tag: user_data.tag.clone(),
        nickname: user_data.nickname.clone(),
        password: hashed_password,
        last_seen: None,
    };

    // Вставляем пользователя в базу данных
    match
        diesel::insert_into(users::table).values(&new_user).execute(&mut conn) // Передаем изменяемую ссылку
    {
        // Если успешно, возвращаем статус 201 (Created)
        Ok(_) => HttpResponse::Created().body("User created successfully"),
        // Если тег уже существует
        Err(
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ),
        ) => {
            HttpResponse::Conflict().body("Tag already exists")
        }
        // В случае других ошибок
        Err(_) => HttpResponse::InternalServerError().body("Error creating user"),
    }
}

pub async fn login_user(
    pool: web::Data<DbPool>,
    user_data: web::Json<LoginData>,
    session: Session
) -> HttpResponse {
    let mut conn = pool.get().unwrap();

    // Ищем пользователя по тегу
    match users::table.filter(users::tag.eq(&user_data.tag)).first::<User>(&mut conn) {
        Ok(user) => {
            // Проверяем введенный пароль с хешем в базе
            match verify(&user_data.password, &user.password) {
                Ok(is_valid) => {
                    if is_valid {
                        // Пароль верный, обновляем поле last_seen
                        let updated_user = diesel
                            ::update(users::table)
                            .filter(users::tag.eq(&user.tag)) // Находим пользователя по тегу
                            .set(users::last_seen.eq(Utc::now().naive_utc())) // Обновляем last_seen на текущее время
                            .execute(&mut conn);

                        match updated_user {
                            Ok(_) => {
                                // Сохраняем идентификатор пользователя в сессии
                                session.insert("user_id", user.id).unwrap();
                                HttpResponse::Ok().body("Login successful")
                            }
                            Err(_) =>
                                HttpResponse::InternalServerError().body(
                                    "Failed to update last_seen"
                                ),
                        }
                    } else {
                        // Пароль неверный
                        HttpResponse::Unauthorized().body("Invalid credentials")
                    }
                }
                Err(_) => {
                    // Ошибка при проверке пароля
                    HttpResponse::InternalServerError().body("Password verification failed")
                }
            }
        }
        Err(diesel::result::Error::NotFound) => {
            // Если пользователь не найден
            HttpResponse::NotFound().body("User not found")
        }
        Err(_) => {
            // Обработка других ошибок
            HttpResponse::InternalServerError().body("Error logging in")
        }
    }
}

pub async fn get_users(pool: web::Data<DbPool>) -> HttpResponse {
    let mut conn = pool.get().unwrap();
    let result = users::table
        .select((tag, nickname, last_seen))
        .load::<(String, String, Option<chrono::NaiveDateTime>)>(&mut conn);

    match result {
        Ok(users_data) => {
            let response: Vec<DisplayUserData> = users_data
                .into_iter()
                .map(|(_tag, _nickname, _last_seen)| DisplayUserData {
                    tag: _tag,
                    nickname: _nickname,
                    last_seen: _last_seen,
                })
                .collect();

            HttpResponse::Ok().json(response)
        }
        Err(_) => { HttpResponse::InternalServerError().body("Error retrieving users") }
    }
}

pub async fn start_convo() {}
