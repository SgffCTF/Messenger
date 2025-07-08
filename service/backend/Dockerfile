FROM rust:1.81
WORKDIR /app

# Копируем только Cargo.toml и Cargo.lock для кэширования зависимостей
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock

# Создаём временный main.rs и собираем зависимости
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

# Копируем реальные исходники и **принудительно пересобираем**  
COPY ./src ./src
RUN touch src/main.rs && cargo build --release  # touch гарантирует пересборку

# Установка postgresql-client и подготовка скриптов
COPY ./wait-for-postgres.sh ./wait-for-postgres.sh
RUN apt-get update && apt-get install -y postgresql-client && rm -rf /var/lib/apt/lists/*
RUN chmod +x wait-for-postgres.sh

# Копирование статики и создание папок
COPY ./static ./static
RUN mkdir backups

# Запуск
CMD ["/bin/sh", "-c", "./wait-for-postgres.sh db ./target/release/backend"]