use tonic::Status;

#[derive(Debug)]
pub enum ServiceError {
    UserAlreadyExists,
    UserNotFound,
    InvalidPassword,
    PasswordHashError(String),
    DatabaseError(String),
    InternalError(String),
}

impl From<sqlx::Error> for ServiceError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::Database(db_err) => {
                if db_err.code().as_deref() == Some("23505") {
                    ServiceError::UserAlreadyExists
                } else {
                    ServiceError::DatabaseError(db_err.message().to_string())
                }
            }
            sqlx::Error::RowNotFound => ServiceError::UserNotFound,
            _ => ServiceError::InternalError(err.to_string()),
        }
    }
}

impl From<argon2::Error> for ServiceError {
    fn from(err: argon2::Error) -> Self {
        ServiceError::PasswordHashError(err.to_string())
    }
}

// Convert your enum into tonic::Status
impl From<ServiceError> for Status {
    fn from(err: ServiceError) -> Self {
        match err {
            ServiceError::UserAlreadyExists => Status::already_exists("User already exists"),
            ServiceError::UserNotFound => Status::not_found("User not found"),
            ServiceError::InvalidPassword => Status::invalid_argument("Invalid password"),
            ServiceError::PasswordHashError(msg) => Status::internal(msg),
            ServiceError::DatabaseError(msg) => Status::internal(msg),
            ServiceError::InternalError(msg) => Status::internal(msg),
        }
    }
}
