# auth-project-SMIT
=====================

## Project Overview
-------------------

auth-project-SMIT is a Python-based authentication project designed to provide secure user authentication and authorization functionality. This project utilizes a combination of Python, Flask, and SQLite to create a robust and scalable authentication system.

## Features
------------

*   User registration and login functionality
*   Secure password hashing and verification
*   Role-based access control (RBAC) for user authorization
*   SQLite database for storing user credentials and permissions

## Tech Stack
-------------

*   **Language:** Python 3.9+
*   **Framework:** Flask 2.0+
*   **Database:** SQLite 3.38+
*   **Testing:** Pytest 7.1+
*   **Linting:** Flake8 5.0+

## Architecture
--------------

The project follows a modular architecture, with the following components:

*   **query_db.py:** Contains database-related functions for interacting with the SQLite database.
*   **requirements.txt:** Lists the project's dependencies, including Flask, SQLite, and Pytest.

### Implementation Summary

For a detailed overview of the project's implementation, please refer to the [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) file.

### Configuration

To configure the project, create a `.env` file with the following environment variables:

*   `SQLITE_DB`: Path to the SQLite database file
*   `SECRET_KEY`: Secret key for secure password hashing and verification

Example `.env` file:
```makefile
SQLITE_DB=/path/to/database.db
SECRET_KEY=your_secret_key_here
```
### Testing

To run the project's tests, execute the following command:
```bash
pytest
```
### Linting

To lint the project's code, execute the following command:
```bash
flake8
```
### Dependencies

To install the project's dependencies, execute the following command:
```bash
pip install -r requirements.txt
```
### Contributing

Contributions to this project are welcome. Please fork the repository, make your changes, and submit a pull request.