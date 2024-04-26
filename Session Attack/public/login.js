// Function to set session ID cookie
function setSessionIdCookie(sessionId) {
    document.cookie = 'sessionId=' + sessionId + ';expires=;path=/';
}

// Function to log session ID on the server
function logSessionId(sessionId) {
    // Send session ID to the server
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/logSessionId');
    xhr.setRequestHeader('Content-Type', 'text/plain');
    xhr.onload = function() {
        if (xhr.status === 200) {
            console.log('Session ID logged successfully');
        } else {
            console.error('Error logging session ID');
        }
    };
    xhr.send(sessionId);
}

// Update login function to set cookie and log session ID
function login() {
    let username = document.getElementById('username').value;
    let password = document.getElementById('password').value;

    // Make a POST request to the server for login validation
    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: 'username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password)
    })
    .then(response => {
        if (response.ok) {
            // If login is successful, redirect to index page
            window.location.href = 'index.html';
            // Also log the session ID
            return response.text(); // Get response body as text (session ID)
        } else {
            // If login fails, display error message
            document.getElementById('loginMessage').textContent = 'Invalid username or password. Please try again.';
            throw new Error('Login failed'); // Throw error to trigger catch block
        }
    })
    .then(sessionId => {
        // Log session ID on the server
        logSessionId(sessionId);
    })
    .catch(error => {
        console.error('Error logging in:', error);
    });
}
