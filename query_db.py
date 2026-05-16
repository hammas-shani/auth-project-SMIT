import sqlite3

conn = sqlite3.connect("./test.db")
cursor = conn.cursor()

# Get all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()
print("📊 Tables in database:")
for table in tables:
    print(f"  - {table[0]}")

# Query users
print("\n" + "=" * 70)
print("USERS TABLE CONTENT:")
print("=" * 70)
cursor.execute(
    "SELECT id, email, hashed_password, is_active, created_at FROM users"
)
rows = cursor.fetchall()
print(f"\n✓ Total users stored: {len(rows)}\n")

for idx, row in enumerate(rows, 1):
    print(f"User #{idx}:")
    print(f"  ID: {row[0]}")
    print(f"  Email: {row[1]}")
    print(f"  Password Hash (bcrypt): {row[2]}")
    print(f"  Is Active: {row[3]}")
    print(f"  Created At: {row[4]}\n")

conn.close()
