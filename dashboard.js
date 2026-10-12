/**
 * AegisGateway - Dashboard Controller
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Double check authentication (loaded via security.js)
    const user = AegisSession.getCurrentUser();
    if (!user) {
        window.location.href = "login.html";
        return;
    }

    // Initialize display fields
    document.getElementById('sessionUsername').textContent = user.username;
    document.getElementById('userFullName').textContent = user.fullName;
    
    // Set up role badge
    const roleBadge = document.getElementById('roleBadge');
    roleBadge.textContent = user.role;
    if (user.role === 'Administrator') {
        roleBadge.className = 'role-badge badge-admin';
    } else {
        roleBadge.className = 'role-badge badge-officer';
    }

    // 2. Role-Based Navigation & Metric Card Visibility Checks
    const isAdmin = (user.role === 'Administrator');
    if (isAdmin) {
        // Show Admin Navigation panels
        document.getElementById('menuUsers').style.display = 'block';
        document.getElementById('menuActivity').style.display = 'block';
        document.getElementById('adminSecurityPanel').style.display = 'block';
        
        // Show Admin Stat Cards & Layout blocks
        document.getElementById('cardUsers').style.display = 'flex';
        document.getElementById('cardActivities').style.display = 'flex';
        document.getElementById('adminDashboardSection').style.display = 'block';
    }

    // 3. Compile Statistics from LocalStorage Database Arrays
    function compileDashboardStats() {
        // A. Users Database Parsing
        const users = JSON.parse(localStorage.getItem('aegis_users')) || [];
        const totalUsers = users.length;
        const activeUsers = users.filter(u => u.status === 'active').length;
        document.getElementById('statTotalUsers').textContent = `${activeUsers} / ${totalUsers}`;

        // B. Messages Database Parsing
        const messages = JSON.parse(localStorage.getItem('aegis_messages')) || [];
        
        // Count inbox details for the current user
        const inboxMsgs = messages.filter(m => m.receiver.toLowerCase() === user.username.toLowerCase());
        const unreadInboxMsgs = inboxMsgs.filter(m => m.status === 'unread');
        
        document.getElementById('statInboxMessages').textContent = inboxMsgs.length;
        document.getElementById('statUnreadCount').textContent = unreadInboxMsgs.length;

        // Count sent details for the current user
        const sentMsgs = messages.filter(m => m.sender.toLowerCase() === user.username.toLowerCase());
        document.getElementById('statSentMessages').textContent = sentMsgs.length;

        // Global System message count (Admin only)
        document.getElementById('statGlobalMessages').textContent = messages.length;

        // C. System Logs Parse
        const logs = JSON.parse(localStorage.getItem('aegis_activities')) || [];

        // D. Populate Recent Timeline Logs
        const timelineList = document.getElementById('recentActivityList');
        timelineList.innerHTML = ''; // Clear loader

        // Filter activities: Admin sees all logs. Officer sees only their own actions.
        const filteredLogs = isAdmin 
            ? logs 
            : logs.filter(l => l.username.toLowerCase() === user.username.toLowerCase());

        if (filteredLogs.length === 0) {
            timelineList.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem;">No recent activities logged in your clearance level.</div>';
        } else {
            // Display up to 5 recent logs
            const recentLogs = filteredLogs.slice(0, 5);
            recentLogs.forEach(log => {
                const itemDiv = document.createElement('div');
                itemDiv.className = 'timeline-item';
                const logDate = new Date(log.date).toLocaleString();

                // Escape logs to prevent XSS
                const safeUsername = SecurityGuard.escapeHTML(log.username);
                const safeAction = SecurityGuard.escapeHTML(log.action);
                const safeDescription = SecurityGuard.escapeHTML(log.description);

                let actionColor = 'var(--accent-primary)';
                if (log.action.toLowerCase().includes('fail') || log.action.toLowerCase().includes('violation')) {
                    actionColor = 'var(--color-danger)';
                } else if (log.action.toLowerCase().includes('success') || log.action.toLowerCase().includes('register')) {
                    actionColor = 'var(--color-success)';
                }

                itemDiv.innerHTML = `
                    <div class="timeline-details">
                        <span class="timeline-action" style="color: ${actionColor}">${safeAction}</span>
                        <span style="color: var(--text-secondary); font-size: 0.82rem;">${safeDescription}</span>
                        <span class="timeline-meta">Triggered by: @${safeUsername}</span>
                    </div>
                    <div class="timeline-meta" style="white-space: nowrap;">${logDate}</div>
                `;
                timelineList.appendChild(itemDiv);
            });
        }

        // E. Render Admin Preview Tables (Admin Only)
        if (isAdmin) {
            renderAdminUsersPreview(users);
            renderAdminMessagesPreview(messages);
        }
    }

    // Render Compact Directory table on Dashboard
    function renderAdminUsersPreview(usersList) {
        const tableBody = document.getElementById('adminUsersTableBody');
        tableBody.innerHTML = '';

        // Display up to 4 users
        const previewList = usersList.slice(0, 4);
        previewList.forEach(userItem => {
            const tr = document.createElement('tr');
            
            const safeName = SecurityGuard.escapeHTML(userItem.fullName);
            const safeUsername = SecurityGuard.escapeHTML(userItem.username);
            const roleBadge = userItem.role === 'Administrator' 
                ? '<span class="user-role-badge role-admin" style="font-size:0.65rem;">Admin</span>' 
                : '<span class="user-role-badge role-officer" style="font-size:0.65rem;">Officer</span>';

            const statusBadge = userItem.status === 'active'
                ? '<span class="status-badge user-status-active" style="font-size:0.65rem; padding: 1px 4px;">Active</span>'
                : '<span class="status-badge user-status-inactive" style="font-size:0.65rem; padding: 1px 4px;">Locked</span>';

            tr.innerHTML = `
                <td><strong>${safeName}</strong></td>
                <td>@${safeUsername}</td>
                <td>${roleBadge}</td>
                <td>${statusBadge}</td>
            `;
            tableBody.appendChild(tr);
        });
    }

    // Render Compact Global Messages table on Dashboard
    function renderAdminMessagesPreview(messagesList) {
        const tableBody = document.getElementById('adminMessagesTableBody');
        tableBody.innerHTML = '';

        if (messagesList.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="4" style="text-align: center; color: var(--text-muted); font-size: 0.8rem; padding: 15px 0;">
                        No transmissions logged.
                    </td>
                </tr>
            `;
            return;
        }

        // Sort newest first, take up to 4
        const previewList = [...messagesList].sort((a,b) => new Date(b.date) - new Date(a.date)).slice(0, 4);
        
        previewList.forEach(msg => {
            const tr = document.createElement('tr');
            const dateStr = new Date(msg.date).toLocaleDateString();

            const safeSender = SecurityGuard.escapeHTML(msg.sender);
            const safeReceiver = SecurityGuard.escapeHTML(msg.receiver);
            const safeSubject = SecurityGuard.escapeHTML(msg.subject);

            tr.innerHTML = `
                <td>@${safeSender}</td>
                <td>@${safeReceiver}</td>
                <td>${safeSubject}</td>
                <td style="font-family: var(--font-mono); font-size: 0.72rem;">${dateStr}</td>
            `;
            tableBody.appendChild(tr);
        });
    }

    compileDashboardStats();

    // 4. Live Clock Ticker in Header Navigation
    function startClock() {
        const clockEl = document.getElementById('headerClock');
        if (!clockEl) return;
        
        function updateTime() {
            const now = new Date();
            const dateStr = now.toISOString().split('T')[0];
            const timeStr = now.toTimeString().split(' ')[0];
            clockEl.textContent = `SYSTEM TIME: ${dateStr} ${timeStr}`;
        }
        
        updateTime();
        setInterval(updateTime, 1000);
    }
    startClock();

    // 5. Logout Session Exit Controls
    function handleLogout(e) {
        e.preventDefault();
        AegisSession.clearSession();
        window.location.href = "login.html";
    }

    document.getElementById('logoutBtnTop').addEventListener('click', handleLogout);
    document.getElementById('logoutBtnSidebar').addEventListener('click', handleLogout);
});
