const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Create an Express app
const app = express();
const port = 5000;

// Middleware to parse JSON request bodies
app.use(express.json());

// Create a connection to the MySQL database
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '12345',
  database: 'STUDENT_PORTAL'
});

// Connect to the database
connection.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err.stack);
    return;
  }
  console.log('Connected to the database as ID ' + connection.threadId);
});

// Signup API
app.post('/signup', (req, res) => {
  const { firstName, lastName, email, password, phoneNumber, dateOfBirth, gender, className, schoolName, description, exams } = req.body;
  const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  // Validate phone number length (should be 10 or more characters)
  if (phoneNumber.length < 10) {
    return res.status(400).json({ error: 'Phone number must be at least 10 characters long' });
  }
  // Check if the email already exists
  connection.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) {
      console.error('Query error:', err.stack);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length > 0) {
      return res.status(400).json({ error: 'Email already in use' });
    }

    // Hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.error('Error hashing password:', err.stack);
        return res.status(500).json({ error: 'Password hashing error' });
      }

      // Insert the user into the database
      const query = 'INSERT INTO users (firstName, lastName, email, password, phoneNumber, dateOfBirth, gender, className, schoolName, description, exams) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
      connection.query(query, [firstName, lastName, email, hashedPassword, phoneNumber, dateOfBirth, gender, className, schoolName, description, JSON.stringify(exams)], (err, results) => {
        if (err) {
          console.error('Query error:', err.stack);
          return res.status(500).json({ error: 'Database error' });
        }
        return res.status(201).json({ message: 'User created successfully' });
      });
    });
  });
});

// Login API
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Find the user by email
  connection.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) {
      console.error('Query error:', err.stack);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = results[0];

    // Compare the password with the hashed password in the database
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error('Error comparing passwords:', err.stack);
        return res.status(500).json({ error: 'Password comparison error' });
      }
      if (!isMatch) {
        return res.status(400).json({ error: 'Invalid password' });
      }

      // Generate a JWT token
      const token = jwt.sign({ userId: user.id }, 'your_jwt_secret', { expiresIn: '1h' });
      return res.status(200).json({ message: 'Login successful', token });
    });
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
