/**
 * AegisGateway - Activity Logs Controller (Admin Only)
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Force Administrator clearance checks
    const currentUser = AegisSession.requireAdmin();
    
    // Initialize common layouts
    initCommonElements();

    const activityTableBody = document.getElementById('activityTableBody');
    const logSearchInput = document.getElementById('logSearch');
    const actionFilterSelect = document.getElementById('actionFilter');
    const clearLogsBtn = document.getElementById('clearLogsBtn');

    // 2. Render Audit Trails
    function renderLogs() {
        const logs = JSON.parse(localStorage.getItem('aegis_activities')) || [];
        const searchQuery = logSearchInput.value.trim().toLowerCase();
        const actionFilter = actionFilterSelect.value;

        // Sort newest first
        let filteredLogs = [...logs].sort((a, b) => new Date(b.date) - new Date(a.date));

        // A. Filter by Keyword (Username, Action, or Description)
        if (searchQuery.length > 0) {
            filteredLogs = filteredLogs.filter(log => 
                log.username.toLowerCase().includes(searchQuery) ||
                log.action.toLowerCase().includes(searchQuery) ||
                log.description.toLowerCase().includes(searchQuery)
            );
        }

        // B. Filter by Action Type Selector Category
        if (actionFilter !== 'all') {
            filteredLogs = filteredLogs.filter(log => {
                const act = log.action.toLowerCase();
                const desc = log.description.toLowerCase();
                
                switch (actionFilter) {
                    case 'auth':
                        return act.includes('login') || act.includes('logout') || act.includes('registration');
                    case 'message':
                        return act.includes('message') || act.includes('outbound') || act.includes('transmission') || act.includes('decrypt');
                    case 'user_mgmt':
                        return act.includes('user created') || act.includes('user modified') || act.includes('user deleted') || act.includes('status toggled');
                    case 'errors':
                        return act.includes('fail') || act.includes('violation') || act.includes('intercepted') || act.includes('denied') || act.includes('aborted');
                    default:
                        return true;
                }
            });
        }

        // Clear table content
        activityTableBody.innerHTML = '';

        if (filteredLogs.length === 0) {
            activityTableBody.innerHTML = `
                <tr>
                    <td colspan="4" style="text-align: center; color: var(--text-muted);">
                        No telemetry logs matching the current filter filters found.
                    </td>
                </tr>
            `;
            return;
        }

        // Inject rows
        filteredLogs.forEach(log => {
            const tr = document.createElement('tr');
            
            // Format Timestamp
            const logDate = new Date(log.date).toLocaleString();

            // Set up log category color text based on action type
            let actionColor = 'var(--accent-primary)'; // default cyan
            const actionLower = log.action.toLowerCase();

            if (actionLower.includes('fail') || actionLower.includes('violation') || actionLower.includes('intercepted') || actionLower.includes('aborted')) {
                actionColor = 'var(--color-danger)'; // Red for failures
            } else if (actionLower.includes('success') || actionLower.includes('created') || actionLower.includes('registration')) {
                actionColor = 'var(--color-success)'; // Green for success/creations
            } else if (actionLower.includes('modified') || actionLower.includes('toggled')) {
                actionColor = 'var(--color-warning)'; // Yellow for modifications
            }

            // Safe XSS shielding - escaping fields before template formatting
            const safeUsername = SecurityGuard.escapeHTML(log.username);
            const safeAction = SecurityGuard.escapeHTML(log.action);
            const safeDescription = SecurityGuard.escapeHTML(log.description);

            tr.innerHTML = `
                <td style="font-family: var(--font-mono); font-size: 0.8rem;">${logDate}</td>
                <td><strong>@${safeUsername}</strong></td>
                <td><span style="color: ${actionColor}; font-weight: 600; font-family: var(--font-heading); font-size: 0.8rem;">${safeAction}</span></td>
                <td style="color: var(--text-secondary);">${safeDescription}</td>
            `;

            activityTableBody.appendChild(tr);
        });
    }

    // 3. Clear System Audit logs
    clearLogsBtn.addEventListener('click', () => {
        const warningMessage = "WARNING: You are about to permanently purge all security audit log history from LocalStorage.\n\nDo you authorize this system clearance?";
        
        if (!confirm(warningMessage)) {
            return;
        }

        // Reset database logs with a single initialization system record
        const freshLogs = [
            {
                username: currentUser.username,
                action: "Logs Purged",
                date: new Date().toISOString(),
                description: "System audit logs database completely purged and re-initialized by administrator."
            }
        ];

        localStorage.setItem('aegis_activities', JSON.stringify(freshLogs));
        renderLogs();
    });

    // Bind event query handlers
    logSearchInput.addEventListener('input', renderLogs);
    actionFilterSelect.addEventListener('change', renderLogs);

    // Initial load
    renderLogs();

    // --- Helpers: Header Clock & Sidebar Management ---
    function initCommonElements() {
        const nameSlot = document.getElementById('sessionUsername');
        if (nameSlot) nameSlot.textContent = currentUser.username;

        const menuUsers = document.getElementById('menuUsers');
        if (menuUsers) menuUsers.style.display = 'block';

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
