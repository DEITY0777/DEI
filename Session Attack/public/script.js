const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public')); // Serve static files from the public directory
app.use(cookieParser()); // Use cookie-parser middleware

let loggedInUsers = {}; // Track logged-in users globally
let usedCredentials = new Set(); // Track credentials that have been used to log in
const maxLoggedInUsers = 2; // Maximum allowed logged-in users per session
const maxLoginsPerCredential = 1; // Maximum allowed logins per credential

// Hardcoded user credentials
const users = [
    { username: 'admin', password: 'admin' },
    { username: 'admin2', password: 'admin2' },
    { username: 'admin3', password: 'admin3' }
    // Add more users as needed
];

// Route for handling login requests
app.post('/login', function(req, res) {
    // Check if the maximum number of users is reached
    if (Object.keys(loggedInUsers).length >= maxLoggedInUsers) {
        res.status(403).send('Maximum number of users logged in');
        return;
    }

    var username = req.body.username;
    var password = req.body.password;

    // Check if the credential has already been used to log in
    if (usedCredentials.has(username)) {
        res.status(403).send('Maximum logins per credential exceeded');
        return;
    }

    // Validate credentials
    const user = users.find(user => user.username === username && user.password === password);
    if (user) {
        // Generate session ID
        var sessionId = generateSessionID();

        // Track logged-in user
        loggedInUsers[sessionId] = { username: username };

        // Log session ID and username to text file
        fs.appendFile('session_ids.txt', `Session ID: ${sessionId}, Username: ${username}\n`, function(err) {
            if (err) console.error('Error logging session ID:', err);
            else console.log('Session ID and username logged:', sessionId, username);
        });

        // Mark credential as used
        usedCredentials.add(username);

        // Set session ID cookie
        res.cookie('sessionId', sessionId);

        // Redirect to index.html with username as a query parameter
        res.status(302).redirect(`/index.html?username=${username}`);
    } else {
        res.status(401).send('Invalid username or password');
    }
});

// Function to generate session ID
function generateSessionID() {
    return Math.random().toString(36).substr(2, 9);
}

app.listen(PORT, function() {
    console.log(`Server is running on port ${PORT}`);
});
