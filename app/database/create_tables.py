"""
Table creation is handled automatically by lifespan in main.py.
This script is kept for reference only.
"""

# Tables are auto-created in app/main.py via lifespan async context manager.
print(
    "Use: uvicorn app.main:app --reload"
    "  (tables created automatically on startup)"
)
