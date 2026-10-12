/**
 * AegisGateway - Registration Controller
 */

// Global Role Selector helper (accessible from HTML inline onclick)
function selectRole(roleValue) {
    const userOpt = document.getElementById('roleUserOpt');
    const adminOpt = document.getElementById('roleAdminOpt');
    const userRadio = document.getElementById('roleUser');
    const adminRadio = document.getElementById('roleAdmin');

    if (roleValue === 'Administrator') {
        adminOpt.classList.add('selected');
        userOpt.classList.remove('selected');
        adminRadio.checked = true;
        userRadio.checked = false;
    } else {
        userOpt.classList.add('selected');
        adminOpt.classList.remove('selected');
        userRadio.checked = true;
        adminRadio.checked = false;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('registerForm');
    const fullNameInput = document.getElementById('fullName');
    const usernameInput = document.getElementById('username');
    const emailInput = document.getElementById('email');
    const mobileInput = document.getElementById('mobile');
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirmPassword');
    const alertContainer = document.getElementById('alertContainer');

    // Live validation element references
    const usernameStatus = document.getElementById('usernameStatus');
    const emailStatus = document.getElementById('emailStatus');
    const mobileStatus = document.getElementById('mobileStatus');
    const confirmStatus = document.getElementById('confirmStatus');
    const strengthLabel = document.getElementById('strengthLabel');
    const bars = [
        document.getElementById('bar1'),
        document.getElementById('bar2'),
        document.getElementById('bar3'),
        document.getElementById('bar4')
    ];

    // Helper: Render Bootstrap-like alerts safely using textContent to prevent XSS
    function displayAlert(message, type) {
        alertContainer.innerHTML = ''; // Clear previous
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert-popup alert-popup-${type}`;
        
        // Escape HTML to prevent XSS
        const safeText = SecurityGuard.escapeHTML(message);
        alertDiv.innerHTML = `<span><strong>ALERT:</strong> ${safeText}</span>`;
        
        alertContainer.appendChild(alertDiv);
        alertDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // 1. Username Real-Time Check
    usernameInput.addEventListener('input', () => {
        const value = usernameInput.value.trim();
        usernameStatus.className = 'input-status active';

        if (value.length === 0) {
            usernameStatus.textContent = '';
            usernameStatus.className = 'input-status';
            return;
        }

        const alphanumericRegex = /^[a-zA-Z0-9]+$/;
        if (!alphanumericRegex.test(value)) {
            usernameStatus.textContent = 'Invalid: Only alphanumeric characters allowed.';
            usernameStatus.className = 'input-status active status-invalid';
            return;
        }

        if (value.length < 3 || value.length > 15) {
            usernameStatus.textContent = 'Invalid: Must be between 3 and 15 characters.';
            usernameStatus.className = 'input-status active status-invalid';
            return;
        }

        // Duplicate Check
        const users = JSON.parse(localStorage.getItem('aegis_users')) || [];
        const isDuplicate = users.some(u => u.username.toLowerCase() === value.toLowerCase());
        
        if (isDuplicate) {
            usernameStatus.textContent = 'Invalid: Username is already registered.';
            usernameStatus.className = 'input-status active status-invalid';
        } else {
            usernameStatus.textContent = 'Valid: Username is available.';
            usernameStatus.className = 'input-status active status-valid';
        }
    });

    // 2. Email Real-Time Check
    emailInput.addEventListener('input', () => {
        const value = emailInput.value.trim();
        emailStatus.className = 'input-status active';

        if (value.length === 0) {
            emailStatus.className = 'input-status';
            return;
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(value)) {
            emailStatus.textContent = 'Invalid: Correct format is name@domain.com.';
            emailStatus.className = 'input-status active status-invalid';
        } else {
            emailStatus.textContent = 'Valid: Email format is correct.';
            emailStatus.className = 'input-status active status-valid';
        }
    });

    // 3. Mobile Number Check
    mobileInput.addEventListener('input', () => {
        const value = mobileInput.value.trim();
        mobileStatus.className = 'input-status active';

        if (value.length === 0) {
            mobileStatus.className = 'input-status';
            return;
        }

        const mobileRegex = /^[0-9]{10}$/;
        if (!mobileRegex.test(value)) {
            mobileStatus.textContent = 'Invalid: Must be exactly 10 digits.';
            mobileStatus.className = 'input-status active status-invalid';
        } else {
            mobileStatus.textContent = 'Valid: Mobile number is correct.';
            mobileStatus.className = 'input-status active status-valid';
        }
    });

    // 4. Password Strength Gauge
    passwordInput.addEventListener('input', () => {
        const value = passwordInput.value;
        let strength = 0;

        if (value.length === 0) {
            updateStrengthMeter(0, "Empty");
            return;
        }

        // Rule 1: Length of 8 or more characters
        if (value.length >= 8) strength++;
        // Rule 2: Contains both upper and lower case letters
        if (/[A-Z]/.test(value) && /[a-z]/.test(value)) strength++;
        // Rule 3: Contains numbers/digits
        if (/[0-9]/.test(value)) strength++;
        // Rule 4: Contains special symbols
        if (/[^A-Za-z0-9]/.test(value)) strength++;

        let label = "Weak";
        if (strength === 2) label = "Fair";
        if (strength === 3) label = "Good";
        if (strength === 4) label = "Strong";

        updateStrengthMeter(strength, label);
        
        // Retrigger password matching check if confirm password has value
        if (confirmPasswordInput.value.length > 0) {
            validateConfirmPassword();
        }
    });

    function updateStrengthMeter(strength, label) {
        strengthLabel.textContent = `Strength: ${label}`;
        
        // Determine color
        let colorClass = 'var(--border-color)';
        if (strength === 1) colorClass = 'var(--color-danger)';
        if (strength === 2) colorClass = 'var(--color-warning)';
        if (strength >= 3) colorClass = 'var(--color-success)';

        bars.forEach((bar, idx) => {
            if (idx < strength) {
                bar.style.backgroundColor = colorClass;
            } else {
                bar.style.backgroundColor = 'var(--border-color)';
            }
        });
    }

    // 5. Confirm Password matching
    function validateConfirmPassword() {
        const pass = passwordInput.value;
        const confirm = confirmPasswordInput.value;
        confirmStatus.className = 'input-status active';

        if (confirm.length === 0) {
            confirmStatus.className = 'input-status';
            return false;
        }

        if (pass !== confirm) {
            confirmStatus.textContent = 'Invalid: Passwords do not match.';
            confirmStatus.className = 'input-status active status-invalid';
            return false;
        } else {
            confirmStatus.textContent = 'Valid: Passwords match.';
            confirmStatus.className = 'input-status active status-valid';
            return true;
        }
    }

    confirmPasswordInput.addEventListener('input', validateConfirmPassword);

    // 6. Submit Validation Check
    registerForm.addEventListener('submit', (e) => {
        e.preventDefault();

        // Retrieve values
        const fullName = fullNameInput.value.trim();
        const username = usernameInput.value.trim();
        const email = emailInput.value.trim();
        const mobile = mobileInput.value.trim();
        const password = passwordInput.value;
        const confirmPassword = confirmPasswordInput.value;
        
        // Retrieve checked role
        const role = document.querySelector('input[name="role"]:checked').value;

        // Reset display errors
        alertContainer.innerHTML = '';

        // Validation A: Check empty inputs
        if (!fullName || !username || !email || !mobile || !password || !confirmPassword) {
            displayAlert("Registration rejected. All gateway credential fields are mandatory.", "danger");
            return;
        }

        // Validation B: Verify Username Rules
        const alphanumericRegex = /^[a-zA-Z0-9]+$/;
        if (!alphanumericRegex.test(username) || username.length < 3 || username.length > 15) {
            displayAlert("Registration rejected. Username must be alphanumeric (3-15 chars).", "danger");
            return;
        }

        // Validation C: Duplicate Username Check
        const users = JSON.parse(localStorage.getItem('aegis_users')) || [];
        const isDuplicate = users.some(u => u.username.toLowerCase() === username.toLowerCase());
        if (isDuplicate) {
            displayAlert("Registration rejected. Username already exists in security registries.", "danger");
            return;
        }

        // Validation D: Email format verify
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            displayAlert("Registration rejected. Invalid gateway email address format.", "danger");
            return;
        }

        // Validation E: Mobile digits check
        const mobileRegex = /^[0-9]{10}$/;
        if (!mobileRegex.test(mobile)) {
            displayAlert("Registration rejected. Mobile must contain exactly 10 digits.", "danger");
            return;
        }

        // Validation F: Password strength check
        // We require at least strength 2 (Fair) for demo purposes, and match
        if (password.length < 8) {
            displayAlert("Registration rejected. Password must be at least 8 characters long.", "danger");
            return;
        }

        if (password !== confirmPassword) {
            displayAlert("Registration rejected. Password confirmations do not match.", "danger");
            return;
        }

        // Create user object
        const newUser = {
            fullName: fullName,
            username: username,
            email: email,
            mobile: mobile,
            password: password, // Frontend demonstration storage
            role: role,
            status: "active",
            createdAt: new Date().toISOString()
        };

        // Save to LocalStorage
        users.push(newUser);
        localStorage.setItem('aegis_users', JSON.stringify(users));

        // Audit Log registration activity
        logActivity(username, "Registration", `New account registered as role: ${role}`);

        // Display Success Alert
        displayAlert("Registry enrollment successful! Redirecting to credentials gate...", "success");

        // Disable submission button
        registerForm.querySelector('button[type="submit"]').disabled = true;

        // Redirect after delay
        setTimeout(() => {
            window.location.href = "login.html";
        }, 2000);
    });
});
