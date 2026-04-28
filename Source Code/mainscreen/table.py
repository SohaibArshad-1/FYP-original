import sqlite3

# Connect to your database file
conn = sqlite3.connect('IDS.db')  # Replace with your DB file
cursor = conn.cursor()

# Get all table names
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

# Loop through each table and get column info
for table in tables:
    table_name = table[0]
    print(f"\nTable: {table_name}")
    
    cursor.execute(f"PRAGMA table_info({table_name});")
    columns = cursor.fetchall()

    print("Columns:")
    for column in columns:
        print(f" - {column[1]} ({column[2]})")  # column[1] = name, column[2] = datatype

# Close connection
conn.close()
