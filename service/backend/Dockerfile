# FROM rust:1.81
# WORKDIR /app
# # Создаём директорию для исходного кода и копируем только файлы манифеста
# COPY ./Cargo.toml ./Cargo.lock ./
# # RUN mkdir src && echo "fn main() {}" > src/main.rs
# # # Скачиваем зависимости. Это кешируется, если Cargo.toml не меняется.
# # RUN cargo build --release
# COPY ./static ./static
# # Копируем исходный код проекта
# COPY ./src ./src
# RUN mkdir backups
# # Сборка финального бинарника
# RUN cargo build --release
# # COPY ./static ./static
# # Запускаем бинарник
# CMD ["./target/release/backend"]

FROM rust:1.81
WORKDIR /app
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
COPY ./static ./static
COPY ./src ./src
COPY ./wait-for-postgres.sh ./wait-for-postgres.sh
RUN cargo build --release
RUN apt-get update && apt-get install -y postgresql-client && rm -rf /var/lib/apt/lists/*
RUN chmod +x wait-for-postgres.sh
RUN mkdir backups
CMD ["/bin/sh", "-c", "./wait-for-postgres.sh db ./target/release/backend"]
