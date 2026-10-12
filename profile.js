/**
 * AegisGateway - Profile & Security Sandbox Controller
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Force authentication checks (enforces sessionStorage session exists)
    const user = AegisSession.getCurrentUser();
    if (!user) {
        window.location.href = "login.html";
        return;
    }

    // Initialize layouts
    initCommonElements();

    // Populate Operator Info
    document.getElementById('profFullName').textContent = user.fullName;
    document.getElementById('profUsername').textContent = `@${user.username}`;
    document.getElementById('profEmail').textContent = user.email;
    document.getElementById('profMobile').textContent = user.mobile;
    
    const roleBadge = document.getElementById('profRoleBadge');
    roleBadge.textContent = user.role;
    if (user.role === 'Administrator') {
        roleBadge.className = 'user-role-badge role-admin';
    } else {
        roleBadge.className = 'user-role-badge role-officer';
    }

    // Form selectors
    const changePasswordForm = document.getElementById('changePasswordForm');
    const passAlertContainer = document.getElementById('passAlertContainer');

    // Helper: Render alerts safely
    function displayAlert(message, type) {
        passAlertContainer.innerHTML = '';
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert-popup alert-popup-${type}`;
        const safeText = SecurityGuard.escapeHTML(message);
        alertDiv.innerHTML = `<span><strong>SECURITY PROTOCOL:</strong> ${safeText}</span>`;
        passAlertContainer.appendChild(alertDiv);
    }

    // 2. Change Password Form Logic
    changePasswordForm.addEventListener('submit', (e) => {
        e.preventDefault();
        passAlertContainer.innerHTML = '';

        const oldPassword = document.getElementById('oldPassword').value;
        const newPassword = document.getElementById('newPassword').value;
        const confirmNewPassword = document.getElementById('confirmNewPassword').value;

        // Validation Checks
        if (!oldPassword || !newPassword || !confirmNewPassword) {
            displayAlert("Password change aborted. Please complete all form inputs.", "danger");
            return;
        }

        if (newPassword.length < 8) {
            displayAlert("Password change aborted. New code must be at least 8 characters.", "danger");
            return;
        }

        if (newPassword !== confirmNewPassword) {
            displayAlert("Password change aborted. New password confirmations do not match.", "danger");
            return;
        }

        // Fetch users database from LocalStorage
        const users = JSON.parse(localStorage.getItem('aegis_users')) || [];
        const matchedIdx = users.findIndex(u => u.username.toLowerCase() === user.username.toLowerCase());

        if (matchedIdx !== -1) {
            // Verify old password match
            const storedPassword = users[matchedIdx].password;
            if (storedPassword !== oldPassword) {
                displayAlert("Password change aborted. Incorrect current password entered.", "danger");
                logActivity(user.username, "Credentials Edit Blocked", "Attempted password modify with wrong old credentials.");
                return;
            }

            // Write new password
            users[matchedIdx].password = newPassword;
            localStorage.setItem('aegis_users', JSON.stringify(users));

            logActivity(user.username, "Password Modified", "Successfully updated operator account clearance key.");
            displayAlert("Clearance code successfully updated in local registry databases.", "success");
            changePasswordForm.reset();
        } else {
            displayAlert("Fatal error: Active session operator profile not found in database.", "danger");
        }
    });

    // 3. Web Crypto Digest SHA-256 Hashing Sandbox
    const hashInput = document.getElementById('hashInput');
    const hashOutput = document.getElementById('hashOutput');

    // Cryptographic function leveraging browser Native Web Crypto digest SHA-256 API
    async function computeSHA256(messageString) {
        if (!messageString) return '-';
        // Encode message string as utf-8 Uint8Array
        const encoder = new TextEncoder();
        const data = encoder.encode(messageString);
        
        // Compute digest hash buffer
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        
        // Convert array buffer to hex string representation
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }

    hashInput.addEventListener('input', async () => {
        const value = hashInput.value;
        if (value.length === 0) {
            hashOutput.textContent = '-';
            return;
        }
        
        try {
            const hexDigest = await computeSHA256(value);
            hashOutput.textContent = hexDigest;
        } catch (err) {
            hashOutput.textContent = 'Hash Engine Error: ' + err.message;
        }
    });

    // 4. Interactive XSS Protection Demonstration Sandbox
    const xssInput = document.getElementById('xssInput');
    const testXssBtn = document.getElementById('testXssBtn');
    const xssOutputDefended = document.getElementById('xssOutputDefended');
    const xssOutputVulnerable = document.getElementById('xssOutputVulnerable');

    testXssBtn.addEventListener('click', () => {
        const payload = xssInput.value;
        if (payload.length === 0) {
            xssOutputDefended.textContent = '-';
            xssOutputVulnerable.textContent = '-';
            return;
        }

        // A. Defended Rendering path: Uses DOM textContent to strictly escape nodes
        xssOutputDefended.textContent = payload;

        // B. Vulnerable Simulation path:
        // Instead of executing innerHTML directly (which pops browser alerts and corrupts UX flow),
        // we detect dangerous patterns to simulate visual XSS execution safely.
        const isDangerous = /<script|onload|onerror|onclick|onmouseover|javascript:/i.test(payload);
        
        if (isDangerous) {
            // Escape the tags for printing but visual-highlight execution alert in red
            const safeDump = SecurityGuard.escapeHTML(payload);
            xssOutputVulnerable.innerHTML = `<span style="color: var(--color-danger); font-weight:700;">[EXPLOT ATTEMPT SUCCESSFUL: Raw innerHTML parsed and executed scripts!]</span><br><code style="color: var(--text-muted);">${safeDump}</code>`;
            logActivity(user.username, "Security Sandbox Trigger", `Simulated XSS exploit execution block. Payload: ${payload}`);
        } else {
            // Non-dangerous elements: simulate standard innerHTML parsing (e.g. rendering html formatting tags like strong/u)
            xssOutputVulnerable.innerHTML = payload;
        }
    });

    // --- Helpers: Header Clock & Sidebar Management ---
    function initCommonElements() {
        const nameSlot = document.getElementById('sessionUsername');
        if (nameSlot) nameSlot.textContent = user.username;

        const isAdmin = (user.role === 'Administrator');
        if (isAdmin) {
            const menuUsers = document.getElementById('menuUsers');
            const menuAct = document.getElementById('menuActivity');
            if (menuUsers) menuUsers.style.display = 'block';
            if (menuAct) menuAct.style.display = 'block';
        }

        const clockEl = document.getElementById('headerClock');
        if (clockEl) {
            function updateTime() {
                const now = new Date();
                const dateStr = now.toISOString().split('T')[0];
                const timeStr = now.toTimeString().split(' ')[0];
                clockEl.textContent = `SYSTEM TIME: ${dateStr} ${timeStr}`;
            }
            updateTime();
            setInterval(updateTime, 1000);
        }

        const handleLogout = (e) => {
            e.preventDefault();
            AegisSession.clearSession();
            window.location.href = "login.html";
        };

        const logoutTop = document.getElementById('logoutBtnTop');
        const logoutSidebar = document.getElementById('logoutBtnSidebar');
        if (logoutTop) logoutTop.addEventListener('click', handleLogout);
        if (logoutSidebar) logoutSidebar.addEventListener('click', handleLogout);
    }
});
