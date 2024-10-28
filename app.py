from flask import Flask, request, jsonify, render_template, redirect, url_for

app = Flask(__name__)

# In-memory storage for demonstration purposes
users = {}  # Dictionary to store users (username: password)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # No validation or hashing
        users[username] = password  # Storing password in plaintext
        return jsonify({"message": "User registered successfully!"}), 201

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Simple authentication without hashing
        if username in users and users[username] == password:
            return jsonify({"message": "Login successful!"}), 200
        return jsonify({"message": "Invalid credentials!"}), 401

    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
