use diesel::table;
use diesel::joinable;
use diesel::allow_tables_to_appear_in_same_query;

table! {
    users (id) {
        id -> Int4,
        tag -> Text,
        nickname -> Text,
        password -> Text,
        last_seen -> Nullable<Timestamp>,
        created_at -> Timestamp,
    }
}

table! {
    conversations (id) {
        id -> Int4,
        created_at -> Timestamp,
    }
}

table! {
    user_conversations (user_id, conversation_id){
        user_id -> Int4,
        conversation_id -> Int4,
    }
}

// Указываем связь между user_conversations и conversations
joinable!(user_conversations -> conversations (conversation_id));

// Указываем связь между user_conversations и users
joinable!(user_conversations -> users (user_id));

allow_tables_to_appear_in_same_query!(users, conversations, user_conversations);
