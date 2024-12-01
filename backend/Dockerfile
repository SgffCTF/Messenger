FROM rust:1.81

WORKDIR /app

# Создаём директорию для исходного кода и копируем только файлы манифеста
COPY ./Cargo.toml ./Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Скачиваем зависимости. Это кешируется, если Cargo.toml не меняется.
RUN cargo build --release

# Копируем исходный код проекта
COPY ./src ./src

# Сборка финального бинарника
RUN cargo build --release

# Запускаем бинарник
CMD ["./target/release/backend"]
