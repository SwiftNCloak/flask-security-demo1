import sqlite3



# Connect to the database

conn = sqlite3.connect('users.db')

cursor = conn.cursor()



# Execute the query to retrieve all data from the table "users"

cursor.execute("SELECT * FROM users")



# Fetch all results as a list of tuples

results = cursor.fetchall()



# Print the results

for row in results:

    print(row) 



# Close the connection

conn.close()