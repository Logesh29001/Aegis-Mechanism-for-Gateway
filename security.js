/**
 * AegisGateway - Security & Utility Core
 * 
 * NOTE: This is a frontend-only demonstration. All security checks, database 
 * tables, and roles are simulated inside the user's browser.
 * This does NOT replace server-side authentication, server-side XSS filtering,
 * or encrypted backend databases.
 */

// 1. Initial Storage Checks
(function initAegisDatabase() {
    if (!localStorage.getItem('aegis_users')) {
        // Create default system admin and basic officer for demo purposes
        const defaultUsers = [
            {
                fullName: "Chief Administrator",
                username: "admin",
                email: "admin@aegis.gov",
                mobile: "9876543210",
                password: "Password@123", // Simulated hash/plain for testing (explained in Phase 10)
                role: "Administrator",
                status: "active",
                createdAt: new Date().toISOString()
            },
            {
                fullName: "Officer James Vance",
                username: "officer1",
                email: "vance@aegis.gov",
                mobile: "9876543211",
                password: "Password@123",
                role: "Officer/User",
                status: "active",
                createdAt: new Date().toISOString()
            }
        ];
        localStorage.setItem('aegis_users', JSON.stringify(defaultUsers));
        console.log("Aegis DB: Initialized default users database.");
    }

    if (!localStorage.getItem('aegis_messages')) {
        localStorage.setItem('aegis_messages', JSON.stringify([]));
        console.log("Aegis DB: Initialized empty messages database.");
    }

    if (!localStorage.getItem('aegis_activities')) {
        const initialLog = [
            {
                username: "system",
                action: "Database Initialized",
                date: new Date().toISOString(),
                description: "Aegis Gateway LocalStorage structures successfully initialized."
            }
        ];
        localStorage.setItem('aegis_activities', JSON.stringify(initialLog));
        console.log("Aegis DB: Initialized activity audit log database.");
    }
})();

// 2. Audit Logging Utility
function logActivity(username, action, description) {
    try {
        const logs = JSON.parse(localStorage.getItem('aegis_activities')) || [];
        const newLog = {
            username: username || "anonymous",
            action: action,
            date: new Date().toISOString(),
            description: description
        };
        logs.unshift(newLog); // Put newest logs at top
        localStorage.setItem('aegis_activities', JSON.stringify(logs));
        console.warn(`[AEGIS AUDIT LOG] User: ${newLog.username} | Action: ${action} | Info: ${description}`);
    } catch (e) {
        console.error("Failed to log activity to LocalStorage:", e);
    }
}

// 3. XSS Sanitization Helpers
const SecurityGuard = {
    /**
     * Escapes unsafe characters to prevent XSS.
     * @param {string} unsafeString - The user inputs
     * @returns {string} Safe text content
     */
    escapeHTML: function(unsafeString) {
        if (!unsafeString) return '';
        return String(unsafeString)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    },

    /**
     * Sanitizes complex strings (stripping common script tags)
     */
    sanitizeInput: function(input) {
        if (typeof input !== 'string') return input;
        // Basic pattern matching to strip dangerous tags (for demo purposes)
        return input.replace(/<script[^>]*>([\s\S]*?)<\/script>/gi, '[REDACTED SCRIPT]');
    },

    /**
     * Safe DOM Injection: Sets textContent instead of innerHTML
     */
    safeRenderText: function(elementId, text) {
        const el = document.getElementById(elementId);
        if (el) {
            el.textContent = text;
        }
    }
};

// 4. Secure Session Management Helpers
const AegisSession = {
    getCurrentUser: function() {
        const userJson = sessionStorage.getItem('aegis_session_user');
        if (!userJson) return null;
        try {
            return JSON.parse(userJson);
        } catch (e) {
            return null;
        }
    },

    setCurrentUser: function(userObj) {
        sessionStorage.setItem('aegis_session_user', JSON.stringify(userObj));
    },

    clearSession: function() {
        const user = this.getCurrentUser();
        if (user) {
            logActivity(user.username, "Logout", "Session successfully terminated by user.");
        }
        sessionStorage.removeItem('aegis_session_user');
    },

    requireAuth: function() {
        const user = this.getCurrentUser();
        if (!user) {
            window.location.href = "login.html";
        }
        return user;
    },

    requireAdmin: function() {
        const user = this.requireAuth();
        if (user.role !== 'Administrator') {
            logActivity(user.username, "Access Violation", "Unauthorized attempt to access Admin console.");
            window.location.href = "dashboard.html?error=unauthorized";
        }
        return user;
    }
};

// Print Tactical Initialization Banner
console.log(`
%c======================================================
     AEGIS MECHANISM GATEWAY ACTIVE (FRONTEND DEMO)
======================================================
XSS Guard: ENABLED
Audit Logging: ACTIVE (Writing to LocalStorage)
Demo Administrator Credentials:
   - Username: admin
   - Password: Password@123
======================================================
`, "color: #00ffcc; font-weight: bold; background-color: #0b0f19; padding: 10px; border-radius: 5px;");
