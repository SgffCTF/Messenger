use diesel::prelude::*;
use actix_web::{ web, HttpResponse };
use actix_session::Session;
use bcrypt::{ hash, DEFAULT_COST };
use bcrypt::verify;
use crate::{ db::DbPool, models::User };
use crate::schema::users::{ self, tag, nickname, last_seen };
use crate::schema::user_conversations;
use crate::schema::conversations;
use crate::schema::messages;
use crate::models::{
    DisplayUserData,
    LoginData,
    NewUser,
    RegisterData,
    StartConvoData,
    ConversationResponse,
    MessageData,
    NewMessage,
    Message,
    ConversationInfo,
};
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

pub async fn get_users(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    // Проверяем, есть ли пользователь в сессии
    let user_id: Option<i32> = match session.get("user_id") {
        Ok(id) => id, // Успешно получили ID
        Err(_) => {
            return HttpResponse::InternalServerError().body("Failed to read session");
        }
    };

    if let Some(_user_id) = user_id {
        // Пользователь залогинен, продолжаем обработку
        let mut conn = pool.get().unwrap();

        // Запрашиваем пользователей
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
            Err(_) => HttpResponse::InternalServerError().body("Error retrieving users"),
        }
    } else {
        // Пользователь не залогинен

        HttpResponse::Unauthorized().body("Unauthorized")
    }
}

pub async fn start_convo(
    pool: web::Data<DbPool>,
    session: Session,
    data: web::Json<StartConvoData>
) -> HttpResponse {
    // Получаем ID текущего пользователя из сессии
    let user_id: Option<i32> = match session.get("user_id") {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Failed to read session");
        }
    };

    if let Some(current_user_id) = user_id {
        let mut conn = match pool.get() {
            Ok(c) => c,
            Err(_) => {
                return HttpResponse::InternalServerError().body("Failed to connect to DB");
            }
        };

        // Ищем получателя по тегу
        let recipient = users::table
            .filter(users::tag.eq(&data.recipient_tag))
            .select(users::id)
            .first::<i32>(&mut conn);

        match recipient {
            Ok(recipient_id) => {
                // Проверяем, есть ли уже разговор между пользователями
                let existing_convo = user_conversations::table
                    .inner_join(conversations::table)
                    .filter(user_conversations::user_id.eq(current_user_id))
                    .filter(user_conversations::user_id.eq(recipient_id))
                    .select(user_conversations::conversation_id)
                    .first::<i32>(&mut conn)
                    .optional();

                match existing_convo {
                    Ok(Some(convo_id)) => {
                        // Уже существует разговор
                        session.insert("convo_id", convo_id).unwrap();
                        HttpResponse::Ok().json(ConversationResponse {
                            conversation_id: convo_id,
                        })
                    }
                    Ok(_) => {
                        // Создаем новый разговор
                        let new_convo_id: i32 = diesel
                            ::insert_into(conversations::table)
                            .default_values()
                            .returning(conversations::id)
                            .get_result(&mut conn)
                            .expect("Failed to create conversation");

                        // Добавляем обоих пользователей в таблицу user_conversations
                        let user_convos = vec![
                            (current_user_id, new_convo_id),
                            (recipient_id, new_convo_id)
                        ];

                        for (user_id, convo_id) in user_convos {
                            diesel
                                ::insert_into(user_conversations::table)
                                .values((
                                    user_conversations::user_id.eq(user_id),
                                    user_conversations::conversation_id.eq(convo_id),
                                ))
                                .execute(&mut conn)
                                .expect("Failed to associate user with conversation");
                        }
                        session.insert("convo_id", new_convo_id).unwrap();
                        HttpResponse::Created().json(ConversationResponse {
                            conversation_id: new_convo_id,
                        })
                    }
                    Err(_) =>
                        HttpResponse::InternalServerError().body("Error checking conversation"),
                }
            }
            Err(_) => HttpResponse::NotFound().body("Recipient not found"),
        }
    } else {
        HttpResponse::Unauthorized().body("Unauthorized")
    }
}

pub async fn get_convos(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    let mut conn = pool.get().unwrap();
    let user_id: Option<i32> = match session.get("user_id") {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Failed to read session");
        }
    };

    if let Some(current_user_id) = user_id {
        // Получаем все переписки пользователя
        let convos = user_conversations::table
            .inner_join(conversations::table)
            .filter(user_conversations::user_id.eq(current_user_id))
            .select(conversations::id)
            .load::<i32>(&mut conn);

        match convos {
            Ok(convo_ids) => {
                let mut convo_info: Vec<ConversationInfo> = Vec::new();

                for convo_id in convo_ids {
                    // Получаем последнее сообщение в переписке
                    let last_message = messages::table
                        .filter(messages::conversation_id.eq(convo_id))
                        .order(messages::sent_at.desc())
                        .first::<Message>(&mut conn)
                        .optional()
                        .unwrap();

                    // Получаем другого участника переписки
                    let other_participant = user_conversations::table
                        .inner_join(users::table)
                        .filter(user_conversations::conversation_id.eq(convo_id))
                        .filter(user_conversations::user_id.ne(current_user_id))
                        .select((users::tag, users::nickname))
                        .first::<(String, String)>(&mut conn)
                        .unwrap();

                    convo_info.push(ConversationInfo {
                        id: convo_id,
                        participant_tag: other_participant.0,
                        participant_nickname: other_participant.1,
                        last_message: last_message.as_ref().map(|msg| msg.content.clone()),
                        last_message_time: last_message.as_ref().map(|msg| msg.sent_at.clone()),
                    });
                }

                HttpResponse::Ok().json(convo_info)
            }
            Err(_) => HttpResponse::InternalServerError().body("Error retrieving conversations"),
        }
    } else {
        HttpResponse::Unauthorized().body("Unauthorized")
    }
}

pub async fn send_message(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<i32>,
    data: web::Json<MessageData>
) -> HttpResponse {
    let mut conn = pool.get().unwrap();
    let user_id: Option<i32> = match session.get("user_id") {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Failed to read session");
        }
    };

    let convo_id = path.into_inner();

    if let Some(current_user_id) = user_id {
        // Проверяем, принадлежит ли пользователь к этой переписке
        let user_in_convo = user_conversations::table
            .filter(user_conversations::user_id.eq(current_user_id))
            .filter(user_conversations::conversation_id.eq(convo_id))
            .first::<(i32, i32)>(&mut conn)
            .optional()
            .unwrap();

        if user_in_convo.is_none() {
            return HttpResponse::Forbidden().body("You don't have access to this conversation");
        }

        let message = NewMessage {
            sender_id: current_user_id,
            conversation_id: convo_id,
            content: data.content.clone(),
        };

        diesel::insert_into(messages::table).values(&message).execute(&mut conn).unwrap();

        HttpResponse::Created().body("Message sent")
    } else {
        HttpResponse::Unauthorized().body("Unauthorized")
    }
}

pub async fn get_messages(
    pool: web::Data<DbPool>,
    session: Session,
    path: web::Path<i32>
) -> HttpResponse {
    let mut conn = pool.get().unwrap();
    let user_id: Option<i32> = match session.get("user_id") {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Failed to read session");
        }
    };

    let convo_id = path.into_inner();

    if let Some(current_user_id) = user_id {
        // Проверяем, принадлежит ли пользователь к этой переписке
        let user_in_convo = user_conversations::table
            .filter(user_conversations::user_id.eq(current_user_id))
            .filter(user_conversations::conversation_id.eq(convo_id))
            .first::<(i32, i32)>(&mut conn)
            .optional()
            .unwrap();

        if user_in_convo.is_none() {
            return HttpResponse::Forbidden().body("You don't have access to this conversation");
        }

        // Получаем сообщения
        let messages = messages::table
            .filter(messages::conversation_id.eq(convo_id))
            .load::<Message>(&mut conn)
            .unwrap();

        HttpResponse::Ok().json(messages)
    } else {
        HttpResponse::Unauthorized().body("Unauthorized")
    }
}
