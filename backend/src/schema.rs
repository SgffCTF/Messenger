use diesel::table;

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
        title -> Text,
        created_at -> Timestamp,
    }
}
