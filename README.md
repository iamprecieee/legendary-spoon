# Legendary Spoon

Legendary Spoon is a FastAPI-based application designed as a playground for learning and experimenting with FastAPI and Clean Architecture principles. The project is open-ended, with no limits on adding new functionalities.

## Project Structure
```
legendary-spoon/
├── alembic/                # Database migrations
├── authentication/         # Authentication module
├── config/                 # Configuration settings
├── core/                   # Core utilities (logging, exceptions)
├── users/                  # User management module
├── main.py                 # Application entry point
├── manage.py               # Utility scripts
├── README.md               # Project documentation
```

## Prerequisites
- Python 3.10+
- SQLite
- FastAPI
- SQLModel
- Alembic
- Loguru

## Setup Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/iamprecieee/legendary-spoon.git
   cd legendary-spoon
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   uv venv
   source .venv/bin/activate
   uv sync
   ```

3. Configure environment variables:
   - Create a `.env` file in the root directory.
   - Add the required variables (e.g., `secret_key`, `google_client_id`, `google_client_secret`).

4. Run database migrations:
   ```bash
   python manage.py migrate
   ```

5. Start the application:
   ```bash
   python manage.py runserver
   ```

## Usage
- **Authentication**: Access authentication endpoints via `/auth`.
- **User Management**: Access user-related endpoints via `/users`.
- **Logging**: Logs are stored in `logs/phantom.log`.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request.