/**
 * AegisGateway - Login Controller
 */

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const rememberMeCheckbox = document.getElementById('rememberMe');
    const togglePasswordBtn = document.getElementById('togglePassword');
    const alertContainer = document.getElementById('alertContainer');

    // 1. Remember Me - Pre-fill username if exists in LocalStorage
    const rememberedUsername = localStorage.getItem('aegis_remembered_user');
    if (rememberedUsername) {
        usernameInput.value = rememberedUsername;
        rememberMeCheckbox.checked = true;
    }

    // 2. Show/Hide Password Toggle
    togglePasswordBtn.addEventListener('click', () => {
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            togglePasswordBtn.textContent = 'HIDE';
        } else {
            passwordInput.type = 'password';
            togglePasswordBtn.textContent = 'SHOW';
        }
    });

    // Helper: Safely render alerts using Security HTML Escaper
    function displayAlert(message, type) {
        alertContainer.innerHTML = '';
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert-popup alert-popup-${type}`;
        
        const safeText = SecurityGuard.escapeHTML(message);
        alertDiv.innerHTML = `<span><strong>ALERT:</strong> ${safeText}</span>`;
        
        alertContainer.appendChild(alertDiv);
    }

    // 3. Submit Validation Check
    loginForm.addEventListener('submit', (e) => {
        e.preventDefault();

        const username = usernameInput.value.trim();
        const password = passwordInput.value;
        const rememberMe = rememberMeCheckbox.checked;

        alertContainer.innerHTML = ''; // Clear prior notices

        // Validation A: Check empty inputs
        if (!username || !password) {
            displayAlert("Clearance denied. Please fill in both credential fields.", "danger");
            logActivity(username || "anonymous", "Authentication Failure", "Attempted login with blank fields.");
            return;
        }

        // Retrieve user list from LocalStorage
        const users = JSON.parse(localStorage.getItem('aegis_users')) || [];

        // Search for user
        const matchedUser = users.find(u => u.username.toLowerCase() === username.toLowerCase());

        // Validation B: Check username and password match
        if (!matchedUser || matchedUser.password !== password) {
            displayAlert("Clearance denied. Invalid username or security password.", "danger");
            logActivity(username, "Authentication Failure", "Provided invalid credentials.");
            return;
        }

        // Validation C: Check account status (active/deactivated)
        if (matchedUser.status !== 'active') {
            displayAlert("Access blocked. This identity token has been deactivated by security administrators.", "danger");
            logActivity(username, "Clearance Intercepted", "Deactivated user attempted to establish gateway connection.");
            return;
        }

        // 4. Successful Authentication Actions
        
        // Formulate user session object (excluding password for simulated secure session)
        const sessionUser = {
            fullName: matchedUser.fullName,
            username: matchedUser.username,
            email: matchedUser.email,
            mobile: matchedUser.mobile,
            role: matchedUser.role,
            status: matchedUser.status,
            createdAt: matchedUser.createdAt
        };

        // Write session details to sessionStorage
        AegisSession.setCurrentUser(sessionUser);

        // Manage Remember Me preference in LocalStorage
        if (rememberMe) {
            localStorage.setItem('aegis_remembered_user', matchedUser.username);
        } else {
            localStorage.removeItem('aegis_remembered_user');
        }

        // Log successful login activity
        logActivity(matchedUser.username, "Login Successful", `Cleared gateway access under role: ${matchedUser.role}`);

        displayAlert("Clearance granted. Handshake successful. Redirecting...", "success");

        // Disable submit button
        loginForm.querySelector('button[type="submit"]').disabled = true;

        // Redirect after delay
        setTimeout(() => {
            window.location.href = "dashboard.html";
        }, 1500);
    });
});
