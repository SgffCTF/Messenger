use crate::db::DbPool;
use crate::schema::users::dsl::*;
use diesel::prelude::*;
use actix_web::cookie::Key;

pub async fn get_user_id_by_tag(pool: &DbPool, _tag: &str) -> Result<i32, diesel::result::Error> {
    let mut conn = pool.get().unwrap();
    users.filter(tag.eq(_tag)).select(id).first::<i32>(&mut conn)
}
pub fn generate_session_key(start_time: u64) -> Key {
    let time_bytes = start_time.to_be_bytes();
    let mut key_bytes = [0u8; 64];
    for (i, byte) in key_bytes.iter_mut().enumerate() {
        *byte = time_bytes[i % 8];
    }
    Key::from(&key_bytes)
}

pub async fn get_nickname_by_id(
    pool: &DbPool,
    user_id: i32
) -> Result<String, diesel::result::Error> {
    use crate::schema::users::dsl::*;
    let mut conn = pool.get().unwrap();
    users.filter(id.eq(user_id)).select(nickname).first::<String>(&mut conn)
}
