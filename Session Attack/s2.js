const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const mysql = require('mysql2');

const app = express();
const PORT = process.env.PORT || 3003;

// Create MySQL connection
const connection = mysql.createConnection({
    host: 'localhost', // Change this to your MySQL host
    user: 'root', // Change this to your MySQL username
    password: 'RohitS', // Change this to your MySQL password
    database: 'APPSEC' // Change this to your MySQL database name
});

// Connect to MySQL
connection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL database:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public')); 
app.use(cookieParser()); 

let loggedInUsers = {}; 
let usedCredentials = new Set(); 
let totalLogins = 0; 

const maxLoggedInUsers = 2; 
const maxLoginsPerCredential = 1; 

app.post('/login', function(req, res) {
    const { username, password } = req.body;

        // Insert user credentials into the database
        const sqlInsert = 'INSERT INTO users (username, password) VALUES (?, ?)';
        connection.query(sqlInsert, [username, password], (err, result) => {
            if (err) {
                console.error('Error inserting user credentials into database:', err);
                return res.status(500).send('Internal Server Error');
            }
            console.log('User credentials inserted into database successfully');
        });

        const sqlSelect = 'SELECT * FROM users WHERE username = ? AND password = ?';
    connection.query(sqlSelect, [username, password], (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).send('Internal Server Error');
        }
        
        if (results.length === 0) {
            return res.status(401).send('Invalid username or password');
        }

        // Check if the maximum number of users is reached
        if (Object.keys(loggedInUsers).length >= maxLoggedInUsers) {
            return res.status(403).send('Maximum number of users logged in');
        }

        // Check if the credential has already been used to log in
        if (usedCredentials.has(username)) {
            return res.status(403).send('Maximum logins per credential exceeded');
        }


        // Generate session ID
        const sessionId = generateSessionID();

        // Set session ID cookie
        res.cookie('sessionId', sessionId, { httpOnly: true, sameSite: 'strict' });

        // Track logged-in user
        loggedInUsers[sessionId] = { username };

        // Log to terminal that a user has logged in
        console.log(`User ${username} logged in`);

        // Mark credential as used
        usedCredentials.add(username);

        // Increment total logins
        totalLogins++;

        // Redirect to index.html with username as a query parameter
        res.redirect(`/index.html?username=${username}`);
    });
});

app.post('/logout', function(req, res) {
    const sessionId = req.cookies.sessionId;

    if (!sessionId || !loggedInUsers[sessionId]) {
        return res.status(400).send('No active session found');
    }

    const username = loggedInUsers[sessionId].username;

    // Remove the session ID from loggedInUsers
    delete loggedInUsers[sessionId];

    // Clear the username from usedCredentials
    usedCredentials.delete(username);

    // Clear session ID cookie
    res.clearCookie('sessionId');

    // Send response indicating successful logout
    res.status(200).send('Logout successful');
});

function generateSessionID() {
    return Math.random().toString(36).substr(2, 9);
}

app.listen(PORT, function() {
    console.log(`Server is running on port ${PORT}`);
});

app.get('/current-user', function(req, res) {
    const sessionId = req.cookies.sessionId;
    const user = loggedInUsers[sessionId];
    res.json(user ? { username: user.username } : { username: null });
});

app.get('/total-logins', function(req, res) {
    res.json({ totalLogins });
});

app.get('/logged-in-users', function(req, res) {
    res.json(Object.values(loggedInUsers).map(user => user.username));
});
