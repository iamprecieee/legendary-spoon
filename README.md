<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Legendary Spoon: Your FastAPI & Clean Architecture Playground!](#legendary-spoon-your-fastapi--clean-architecture-playground)
  - [What's Legendary Spoon? 🚀](#whats-legendary-spoon-)
  - [Key Features ✨](#key-features-)
  - [Project Structure 🏗️](#project-structure-)
  - [Prerequisites 🛠️](#prerequisites-)
  - [Setup Instructions ⚙️](#setup-instructions-)
  - [Usage 💡](#usage-)
  - [License 📄](#license-)
  - [Contributing 🤝](#contributing-)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Legendary Spoon: Your FastAPI & Clean Architecture Playground!

## What's Legendary Spoon? 🚀

Legendary Spoon is a FastAPI-based application designed as a playground
for learning and experimenting with **FastAPI** and **Clean Architecture principles**.
The project is open-ended, with no limits on adding new functionalities.

## Key Features ✨

*   **Clean Architecture**: A well-organized, scalable, and maintainable codebase with clear separation of concerns (Application, Domain, Infrastructure, Presentation layers).
*   **FastAPI**: Leverage the power of a modern, fast (high-performance), web framework for building APIs with Python 3.10+.
*   **SQLModel & Alembic**: Seamless asynchronous ORM (Object Relational Mapper) with Pydantic-based models and robust database migrations for SQLite.
*   **JWT Authentication**: Secure user authentication and authorization using JSON Web Tokens, including refresh token mechanisms and blacklisting.
*   **Google OAuth Integration**: Easily integrate social logins with Google, complete with user linking capabilities.
*   **Centralized Exception Handling**: Global error handling for consistent API responses across various types of exceptions (validation, database, HTTP).
*   **Structured Logging with Loguru**: Comprehensive and customizable logging with request context tracking, file rotation, and error-specific logs.
*   **Redis Caching**: Efficient in-memory data caching for improved performance.
*   **Sensitive Data Sanitization**: Built-in sanitization to protect sensitive information in logs and outputs.
*   **CLI Management Tool**: A `manage.py` script for common development tasks like migrations and server management.
*   **Comprehensive Docstrings**: Every major class, function, and method is now meticulously documented for easy understanding and onboarding!

## Project Structure 🏗️

```
legendary-spoon/
├── alembic/                # Database migrations powered by Alembic
├── authentication/         # Handles all aspects of user authentication (local, JWT, OAuth)
│   ├── application/        # Business rules and use cases for authentication
│   ├── domain/             # Core authentication entities (e.g., tokens, blacklisted tokens)
│   ├── infrastructure/     # Integrates with external services (password hashing, JWT handling, OAuth providers)
│   └── presentation/       # API endpoints for authentication (login, register, refresh, logout, OAuth flows)
├── config/                 # Application configuration settings (base, database, etc.)
├── core/                   # Shared utilities and foundational components
│   ├── application/        # Common application interfaces (e.g., caching service interface)
│   ├── infrastructure/     # Core infrastructure components (caching, exception handling, logging)
│   └── presentation/       # Standard API response models
├── users/                  # Manages user-related functionalities
│   ├── application/        # Business rules and use cases for user management
│   ├── domain/             # Core user entity
│   ├── infrastructure/     # Integrates with user data storage (database repository)caching,
│   └── presentation/       # API endpoints for user-related operations (e.g., get current user)
├── main.py                 # The main FastAPI application entry point
├── manage.py               # Command-line utility scripts for development tasks
├── README.md               # You're reading it! Project documentation
└── pyproject.toml          # Project dependencies and metadata (managed by `uv`)
```

## Prerequisites 🛠️

Before you start, make sure you have:

*   **Python 3.10+**: The project is developed and tested with Python 3.10 and above.
*   **SQLite**: The default database for development.
*   **uv**: A modern, fast Python package installer and dependency manager.

## Setup Instructions ⚙️

Getting Legendary Spoon up and running is a breeze!

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/iamprecieee/legendary-spoon.git
    cd legendary-spoon
    ```

2.  **Create a virtual environment and install dependencies:**
    ```bash
    uv venv
    source .venv/bin/activate
    uv sync
    ```

3.  **Configure environment variables:**
    *   Create a `.env` file in the root directory.
    *   Add the required variables. Check `config/base.py` for a full list of settings. Essential ones include:
        *   `SECRET_KEY="your_super_secret_key_here"`
        *   `GOOGLE_CLIENT_ID="your_google_client_id"` (Required for Google OAuth)
        *   `GOOGLE_CLIENT_SECRET="your_google_client_secret"` (Required for Google OAuth)
        *   `GOOGLE_REDIRECT_URI="http://localhost:8001/auth/google/callback"` (For Google OAuth, adjust if your app runs on a different port)
        *   `LOGGING_LEVEL="INFO"` (or "DEBUG", "WARNING", etc.)

4.  **Run database migrations:**
    ```bash
    python manage.py migrate
    ```

5.  **Start the application:**
    ```bash
    python manage.py runserver
    ```

    Your FastAPI application will now be running at `http://localhost:8001`!

## Usage 💡

Explore the API endpoints and functionalities:

*   **Interactive API Docs**: Once the server is running, head over to `http://localhost:8001/docs` (Swagger UI) or `http://localhost:8001/redoc` (ReDoc) to interact with the API endpoints. All endpoints now feature detailed docstrings for easy understanding!
*   **Authentication Endpoints**: All authentication-related operations (register, login, refresh tokens, logout, Google OAuth) are available under the `/auth` prefix.
*   **User Management Endpoints**: User-specific operations, such as fetching the current user details (`/users/me`), are available under the `/users` prefix.
*   **Logging**: Check the `logs/phantom.log` file for detailed application logs. Critical errors are also logged to `logs/phantom_errors.log`.

## License 📄

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing 🤝

Contributions are absolutely welcome! If you have ideas, bug fixes, or new features, please fork the repository and submit a pull request.
Let's make Legendary Spoon even more legendary together!
