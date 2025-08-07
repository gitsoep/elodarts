# ELOdarts

A Flask-based web application for tracking darts players' ELO ratings, match history, and statistics.

## Features

- ELO rating system for darts players
- Match history tracking
- Player statistics (180s and highest finishes)
- User authentication and registration
- Admin panel for user management
- Email notifications for new registrations
- Responsive web interface
- Dockerized deployment with health checks
- Automatic container restart on failure

## Prerequisites

- Docker
- Docker Compose

## Quick Start with Docker

1. Clone the repository:
   ```bash
   git clone https://github.com/gitsoep/elodarts.git
   cd elodarts
   ```

2. Create environment file:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and set your configuration values.

3. Build and start the application:
   ```bash
   docker-compose up -d
   ```

4. Access the application at http://localhost:5000

The application includes:
- Automatic health checks
- Container restart on failure
- Volume mounting for persistent data
- Environment variable configuration
- Log rotation

## Development

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Unix/macOS
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the development server:
```bash
python run.py
```

## Configuration

Configuration is managed through environment variables in the `.env` file:

- `SECRET_KEY`: Flask secret key for session security
- `DATABASE_URL`: SQLite database URL (default: sqlite:///elo.db)
- `MAIL_SERVER`: SMTP server for email notifications
- `MAIL_PORT`: SMTP port (default: 587)
- `MAIL_USE_TLS`: Use TLS for email (True/False)
- `MAIL_USERNAME`: Email username
- `MAIL_PASSWORD`: Email password
- `FLASK_ENV`: Application environment (development/production)
- `PORT`: Application port (default: 5000)

## Docker Commands

- View logs:
  ```bash
  docker-compose logs -f
  ```

- Stop application:
  ```bash
  docker-compose down
  ```

## Project Structure

```
elodarts/
├── app/
│   ├── __init__.py          # Application factory and config
│   ├── models.py            # Database models
│   ├── routes.py            # Application routes
│   ├── static/
│   │   └── style.css        # Application styles
│   └── templates/
│       ├── admin.html       # Admin management interface
│       ├── base.html        # Base template
│       ├── home.html        # Homepage with rankings
│       ├── login.html       # Login form
│       ├── register.html    # Registration form
│       ├── matches.html     # Match history
│       └── stats.html       # Player statistics
├── instance/               # Instance-specific data
│   └── elo.db             # SQLite database
├── .env                   # Environment variables (not in git)
├── .env.example           # Example environment variables
├── Dockerfile             # Multi-stage Docker build
├── docker-compose.yaml    # Docker Compose configuration
├── requirements.txt       # Python dependencies
└── run.py                # Application entry point
```

## Security Features

- Password hashing with Werkzeug
- Protected admin routes
- Email verification for new users
- Environment-based configuration
- TLS support for email
- SQLite database in protected instance folder

## License

MIT License

docker-compose down && docker-compose build && docker-compose up -d