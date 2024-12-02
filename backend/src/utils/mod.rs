use crate::db::DbPool;
use crate::schema::users::dsl::*;
use diesel::prelude::*;

pub async fn get_user_id_by_tag(pool: &DbPool, _tag: &str) -> Result<i32, diesel::result::Error> {
    let mut conn = pool.get().unwrap();
    users.filter(tag.eq(_tag)).select(id).first::<i32>(&mut conn)
}
