use serde::{ Deserialize, Serialize };
use diesel::{ Queryable, Insertable };
use crate::schema::users;
use crate::schema::messages;

#[derive(Serialize, Deserialize, Queryable, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub tag: String,
    pub nickname: String,
    pub password: String,
    pub last_seen: Option<chrono::NaiveDateTime>,
}

#[derive(Serialize, Deserialize, Queryable, Insertable)]
#[diesel(table_name = users)]
pub struct User {
    pub id: i32,
    pub tag: String,
    pub nickname: String,
    pub password: String,
    pub last_seen: Option<chrono::NaiveDateTime>,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Deserialize)]
pub struct RegisterData {
    pub tag: String,
    pub nickname: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginData {
    pub tag: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct DisplayUserData {
    pub tag: String,
    pub nickname: String,
    pub last_seen: Option<chrono::NaiveDateTime>,
}

#[derive(Deserialize)]
pub struct StartConvoData {
    pub recipient_tag: String,
}

#[derive(serde::Serialize)]
pub struct ConversationResponse {
    pub conversation_id: i32,
}

#[derive(Deserialize)]
pub struct MessageData {
    pub content: String,
}

#[derive(Serialize, Deserialize, Queryable, Insertable)]
#[diesel(table_name = messages)]
pub struct NewMessage {
    pub conversation_id: i32,
    pub sender_id: i32,
    pub content: String,
}

#[derive(Serialize, Deserialize, Queryable, Insertable)]
#[diesel(table_name = messages)]
pub struct Message {
    pub id: i32,
    pub conversation_id: i32,
    pub sender_id: i32,
    pub content: String,
    pub sent_at: chrono::NaiveDateTime,
}

#[derive(Serialize, Deserialize)]
pub struct ConversationInfo {
    pub id: i32,
    pub participant_tag: String,
    pub participant_nickname: String,
    pub last_message: Option<String>,
    pub last_message_time: Option<chrono::NaiveDateTime>,
}
