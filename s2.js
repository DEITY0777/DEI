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
let totalLogins = 0; // Track total logins
const maxLoggedInUsers = 2; // Maximum allowed logged-in users per session
const maxLoginsPerCredential = 1; // Maximum allowed logins per credential

// Hardcoded user credentials (ideally, this should come from a database)
const users = [
    { username: 'admin', password: 'admin' },
    { username: 'admin2', password: 'admin2' },
    { username: 'admin3', password: 'admin3' }
    // Add more users as needed
];

// Route for handling login requests
// Add a custom header to the PowerShell request
// Route for handling login requests
app.post('/login', function(req, res) {
    const userAgent = req.get('User-Agent');
    const xClient = req.get('X-Client');

    if ((!userAgent.includes('Mozilla') && !userAgent.includes('Chrome') && !userAgent.includes('Safari')) || xClient === 'Terminal') {
        console.log(`Possible attack detected from client: ${userAgent || 'Unknown browser'}`);
        return res.status(403).send('Forbidden');
    }


    // Check if the maximum number of users is reached
    if (Object.keys(loggedInUsers).length >= maxLoggedInUsers) {
        return res.status(403).send('Maximum number of users logged in');
    }

    const { username, password } = req.body;

    // Check if the credential has already been used to log in
    if (usedCredentials.has(username)) {
        return res.status(403).send('Maximum logins per credential exceeded');
    }

    // Validate credentials
    const user = users.find(user => user.username === username && user.password === password);
    if (!user) {
        return res.status(401).send('Invalid username or password');
    }

    // Generate session ID
    const sessionId = generateSessionID();

    // Set session ID cookie
    res.cookie('sessionId', sessionId, { httpOnly: true, sameSite: 'strict' });

    // Track logged-in user
    loggedInUsers[sessionId] = { username: user.username };

    // Log to terminal that a user has logged in
    console.log(`User ${username} logged in from ${userAgent}`);

    // Mark credential as used
    usedCredentials.add(username);

    // Increment total logins
    totalLogins++;

    // Redirect to index.html with username as a query parameter
    res.redirect(`/index.html?username=${user.username}`);
});




// Route for handling logout requests
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

// Function to generate session ID
function generateSessionID() {
    return Math.random().toString(36).substr(2, 9);
}

app.listen(PORT, function() {
    console.log(`Server is running on port ${PORT}`);
});

// Route to get current logged-in user
app.get('/current-user', function(req, res) {
    const sessionId = req.cookies.sessionId;
    const user = loggedInUsers[sessionId];
    res.json(user ? { username: user.username } : { username: null });
});

// Route to get total logins
app.get('/total-logins', function(req, res) {
    res.json({ totalLogins });
});

// Route to get list of currently logged-in users
app.get('/logged-in-users', function(req, res) {
    res.json(Object.values(loggedInUsers).map(user => user.username));
});
