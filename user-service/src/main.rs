use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use std::sync::Arc;

use sqlx::{PgPool, query_as};
use tonic::{Request, Response, Status, transport::Server};
use user::user_service_server::{UserService, UserServiceServer};
use user::{LoginRequest, LoginResponse};

use crate::{
    error::ServiceError,
    user::{RegisterRequest, RegisterResponse},
};

pub mod error;
pub mod user {
    tonic::include_proto!("user");
}

#[derive(Debug)]
pub struct MyUserService {
    pg: Arc<PgPool>,
}

pub struct UserLogin {
    pub username: String,
    pub password: String,
}

#[tonic::async_trait]
impl UserService for MyUserService {
    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let req = request.into_inner();
        let pg = self.pg.clone();

        let user: UserLogin = query_as!(
            UserLogin,
            "SELECT username, password FROM users WHERE username = $1",
            req.username
        )
        .fetch_one(&*pg)
        .await
        .map_err(ServiceError::from)?;

        let parsed_hash =
            PasswordHash::new(&user.password).map_err(|_| ServiceError::InvalidPassword)?;

        Argon2::default()
            .verify_password(req.password.as_bytes(), &parsed_hash)
            .map_err(|_| ServiceError::InvalidPassword)?;

        Ok(Response::new(LoginResponse { status: 0 })) // success
    }

    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();
        let pg = self.pg.clone();

        let argon2 = Argon2::default();
        let salt = SaltString::generate(OsRng);

        let password_hash = argon2
            .hash_password(req.password.as_bytes(), &salt)
            .map_err(|_| ServiceError::InvalidPassword)?;

        let result = sqlx::query!(
            "INSERT INTO users (name, username, password) VALUES ($1, $2, $3)",
            req.name,
            req.username,
            password_hash.to_string()
        )
        .execute(&*pg)
        .await
        .map_err(ServiceError::from)?;

        if result.rows_affected() == 0 {
            return Err(Status::internal("Insert affected no rows"));
        }

        Ok(Response::new(RegisterResponse { status: 0 })) // success
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let database_url = std::env::var("DATABASE_URL")?;
    let pool = PgPool::connect(&database_url).await?;
    let service = MyUserService { pg: Arc::new(pool) };

    println!("UserService running at {addr}");
    Server::builder()
        .add_service(UserServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
