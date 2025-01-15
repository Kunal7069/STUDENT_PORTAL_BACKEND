require('dotenv').config();

const express = require('express');
const { Client } = require('pg');  // Use pg library for PostgreSQL
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 5000;

app.use(express.json());

// PostgreSQL connection string from Render's external database URL
const client = new Client({
  connectionString: process.env.DB_CONNECTION_STRING,
  ssl: {
    rejectUnauthorized: false,  // Render requires SSL
  },
});

// Connect to the PostgreSQL database
client.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err.stack);
    return;
  }
  console.log('Connected to the PostgreSQL database');
});



app.get('/check-users-table', (req, res) => {
    const checkTableQuery = `
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_name = 'users'
      );
    `;
  
    client.query(checkTableQuery, (err, result) => {
      if (err) {
        console.error('Query error:', err.stack);
        return res.status(500).json({ error: 'Database error' });
      }
  
      if (result.rows[0].exists) {
        return res.status(200).json({ message: 'Table "users" exists.' });
      } else {
        // Create the table if it doesn't exist
        const createTableQuery = `
          CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            firstName VARCHAR(100),
            lastName VARCHAR(100),
            email VARCHAR(100) UNIQUE,
            password VARCHAR(255),
            phoneNumber VARCHAR(15),
            dateOfBirth DATE,
            gender VARCHAR(10),
            className VARCHAR(50),
            schoolName VARCHAR(100),
            description TEXT,
            exams JSONB
          );
        `;
  
        client.query(createTableQuery, (err, result) => {
          if (err) {
            console.error('Error creating table:', err.stack);
            return res.status(500).json({ error: 'Table creation failed' });
          }
          return res.status(201).json({ message: 'Table "users" created successfully.' });
        });
      }
    });
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
  client.query('SELECT * FROM users WHERE email = $1', [email], (err, results) => {
    if (err) {
      console.error('Query error:', err.stack);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.rows.length > 0) {
      return res.status(400).json({ error: 'Email already in use' });
    }

    // Hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.error('Error hashing password:', err.stack);
        return res.status(500).json({ error: 'Password hashing error' });
      }

      // Insert the user into the database
      const query = 'INSERT INTO users (firstName, lastName, email, password, phoneNumber, dateOfBirth, gender, className, schoolName, description, exams) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)';
      client.query(query, [firstName, lastName, email, hashedPassword, phoneNumber, dateOfBirth, gender, className, schoolName, description, JSON.stringify(exams)], (err, results) => {
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
  client.query('SELECT * FROM users WHERE email = $1', [email], (err, results) => {
    if (err) {
      console.error('Query error:', err.stack);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = results.rows[0];

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
