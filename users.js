/**
 * AegisGateway - User Management Controller (Admin Only)
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Force Administrator clearance checks
    const currentUser = AegisSession.requireAdmin();
    
    // Initialize common layouts
    initCommonElements();

    const usersTableBody = document.getElementById('usersTableBody');
    const userSearchInput = document.getElementById('userSearch');
    const addUserForm = document.getElementById('addUserForm');
    const createAlertContainer = document.getElementById('createAlertContainer');
    
    // Edit Modal references
    const editModal = document.getElementById('editUserModalOverlay');
    const editUserForm = document.getElementById('editUserForm');
    const editAlertContainer = document.getElementById('editAlertContainer');
    const editUsernameHidden = document.getElementById('editUsernameHidden');
    const editFullName = document.getElementById('editFullName');
    const editEmail = document.getElementById('editEmail');
    const editMobile = document.getElementById('editMobile');
    const editRole = document.getElementById('editRole');
    const editStatus = document.getElementById('editStatus');
    
    const closeEditModalBtn = document.getElementById('closeEditModalBtn');
    const closeEditModalBtnFooter = document.getElementById('closeEditModalBtnFooter');

    // Helper: Render alerts safely to block XSS
    function displayAlert(container, message, type) {
        container.innerHTML = '';
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert-popup alert-popup-${type}`;
        const safeText = SecurityGuard.escapeHTML(message);
        alertDiv.innerHTML = `<span><strong>ADMIN PROTOCOL:</strong> ${safeText}</span>`;
        container.appendChild(alertDiv);
    }

    // 2. Render Users Directory List
    function renderUsers() {
        const users = JSON.parse(localStorage.getItem('aegis_users')) || [];
        const searchQuery = userSearchInput.value.trim().toLowerCase();

        // Filter directories matching query string
        let filteredUsers = users;
        if (searchQuery.length > 0) {
            filteredUsers = users.filter(u => 
                u.fullName.toLowerCase().includes(searchQuery) ||
                u.username.toLowerCase().includes(searchQuery) ||
                u.email.toLowerCase().includes(searchQuery)
            );
        }

        // Clean directory table
        usersTableBody.innerHTML = '';

        filteredUsers.forEach(userItem => {
            const tr = document.createElement('tr');
            
            const isSelf = (userItem.username.toLowerCase() === currentUser.username.toLowerCase());
            
            // Format badges
            const roleBadge = userItem.role === 'Administrator' 
                ? '<span class="user-role-badge role-admin">Admin</span>' 
                : '<span class="user-role-badge role-officer">Officer</span>';

            const statusBadge = userItem.status === 'active'
                ? '<span class="status-badge user-status-active">Active</span>'
                : '<span class="status-badge user-status-inactive">Suspended</span>';

            // Escape variables against XSS before DOM mounting
            const safeName = SecurityGuard.escapeHTML(userItem.fullName);
            const safeUsername = SecurityGuard.escapeHTML(userItem.username);
            const safeEmail = SecurityGuard.escapeHTML(userItem.email);

            // Configure action buttons. Self editing/deletion has safety overrides.
            const editBtn = `<button class="btn btn-primary btn-sm edit-btn" data-username="${safeUsername}" style="padding: 2px 6px;">Edit</button>`;
            
            const statusBtn = isSelf 
                ? `<button class="btn btn-secondary btn-sm" disabled style="padding: 2px 6px; opacity:0.5; cursor:not-allowed;">Lock</button>`
                : `<button class="btn btn-secondary btn-sm toggle-status-btn" data-username="${safeUsername}" style="padding: 2px 6px;">Toggle</button>`;

            const deleteBtn = isSelf
                ? `<button class="btn btn-secondary btn-sm" disabled style="padding: 2px 6px; opacity:0.5; cursor:not-allowed;">Del</button>`
                : `<button class="btn btn-secondary btn-sm delete-user-btn" data-username="${safeUsername}" style="padding: 2px 6px; border-color:var(--color-danger); color:var(--color-danger);">Del</button>`;

            tr.innerHTML = `
                <td><strong>${safeName} ${isSelf ? '(You)' : ''}</strong></td>
                <td>@${safeUsername}</td>
                <td>${safeEmail}</td>
                <td>${roleBadge}</td>
                <td>${statusBadge}</td>
                <td>
                    ${editBtn}
                    ${statusBtn}
                    ${deleteBtn}
                </td>
            `;

            usersTableBody.appendChild(tr);
        });
    }

    // 3. Register New User Node
    addUserForm.addEventListener('submit', (e) => {
        e.preventDefault();
        createAlertContainer.innerHTML = '';

        const fullName = document.getElementById('newFullName').value.trim();
        const username = document.getElementById('newUsername').value.trim();
        const email = document.getElementById('newEmail').value.trim();
        const mobile = document.getElementById('newMobile').value.trim();
        const role = document.getElementById('newRole').value;
        const password = document.getElementById('newPassword').value;

        // Validation Checks
        if (!fullName || !username || !email || !mobile || !password) {
            displayAlert(createAlertContainer, "Registry failed. All fields are mandatory.", "danger");
            return;
        }

        const alphanumericRegex = /^[a-zA-Z0-9]+$/;
        if (!alphanumericRegex.test(username) || username.length < 3 || username.length > 15) {
            displayAlert(createAlertContainer, "Username must be alphanumeric (3-15 chars).", "danger");
            return;
        }

        const users = JSON.parse(localStorage.getItem('aegis_users')) || [];
        const isDuplicate = users.some(u => u.username.toLowerCase() === username.toLowerCase());
        if (isDuplicate) {
            displayAlert(createAlertContainer, "Username is already enrolled in the registry.", "danger");
            return;
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            displayAlert(createAlertContainer, "Invalid email address format.", "danger");
            return;
        }

        const mobileRegex = /^[0-9]{10}$/;
        if (!mobileRegex.test(mobile)) {
            displayAlert(createAlertContainer, "Mobile must be exactly 10 digits.", "danger");
            return;
        }

        if (password.length < 8) {
            displayAlert(createAlertContainer, "Temporary password must be at least 8 characters.", "danger");
            return;
        }

        // Insert new user object
        const newUser = {
            fullName: fullName,
            username: username,
            email: email,
            mobile: mobile,
            role: role,
            password: password,
            status: "active",
            createdAt: new Date().toISOString()
        };

        users.push(newUser);
        localStorage.setItem('aegis_users', JSON.stringify(users));

        logActivity(
            currentUser.username, 
            "User Created", 
            `Authorized operator account: @${username} (${fullName}) as role: ${role}`
        );

        displayAlert(createAlertContainer, `User Node @${username} registered successfully!`, "success");
        addUserForm.reset();
        renderUsers();
    });

    // 4. Directory Quick Actions Interception
    usersTableBody.addEventListener('click', (e) => {
        const username = e.target.getAttribute('data-username');
        if (!username) return;

        if (e.target.classList.contains('edit-btn')) {
            openEditModal(username);
        } else if (e.target.classList.contains('toggle-status-btn')) {
            toggleUserStatus(username);
        } else if (e.target.classList.contains('delete-user-btn')) {
            deleteUser(username);
        }
    });

    // A. Edit User Modal Populator
    function openEditModal(username) {
        editAlertContainer.innerHTML = '';
        const users = JSON.parse(localStorage.getItem('aegis_users')) || [];
        const target = users.find(u => u.username.toLowerCase() === username.toLowerCase());
        
        if (!target) return;

        editUsernameHidden.value = target.username;
        editFullName.value = target.fullName;
        editEmail.value = target.email;
        editMobile.value = target.mobile;
        editRole.value = target.role;
        editStatus.value = target.status;

        // Open Modal Overlay
        editModal.classList.add('active');
    }

    // B. Save User Details
    editUserForm.addEventListener('submit', (e) => {
        e.preventDefault();
        editAlertContainer.innerHTML = '';

        const username = editUsernameHidden.value;
        const fullName = editFullName.value.trim();
        const email = editEmail.value.trim();
        const mobile = editMobile.value.trim();
        const role = editRole.value;
        const status = editStatus.value;

        // Validation Checks
        if (!fullName || !email || !mobile) {
            displayAlert(editAlertContainer, "Save failed. Missing vital entries.", "danger");
            return;
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            displayAlert(editAlertContainer, "Invalid email address format.", "danger");
            return;
        }

        const mobileRegex = /^[0-9]{10}$/;
        if (!mobileRegex.test(mobile)) {
            displayAlert(editAlertContainer, "Mobile must be exactly 10 digits.", "danger");
            return;
        }

        const isSelf = (username.toLowerCase() === currentUser.username.toLowerCase());
        
        // Prevent Self-Lockout (Admin safety rules)
        if (isSelf) {
            if (status === 'inactive') {
                displayAlert(editAlertContainer, "Clearance Denied: You cannot suspend your own administrative session.", "danger");
                return;
            }
            if (role !== 'Administrator') {
                displayAlert(editAlertContainer, "Clearance Denied: You cannot demote your own admin authorization tier.", "danger");
                return;
            }
        }

        // Write updates
        const users = JSON.parse(localStorage.getItem('aegis_users')) || [];
        const matchedIdx = users.findIndex(u => u.username.toLowerCase() === username.toLowerCase());
        
        if (matchedIdx !== -1) {
            users[matchedIdx].fullName = fullName;
            users[matchedIdx].email = email;
            users[matchedIdx].mobile = mobile;
            users[matchedIdx].role = role;
            users[matchedIdx].status = status;

            localStorage.setItem('aegis_users', JSON.stringify(users));

            logActivity(
                currentUser.username, 
                "User Modified", 
                `Modified details for @${username} (Name: ${fullName}, Role: ${role}, Status: ${status})`
            );

            // If modifying self, update current sessionStorage profile details immediately
            if (isSelf) {
                const updatedSession = { ...currentUser, fullName, email, mobile, role, status };
                AegisSession.setCurrentUser(updatedSession);
                initCommonElements(); // Refresh displays
            }

            closeEditModal();
            renderUsers();
        }
    });

    // C. Activate / Deactivate Operator Status Quick Button
    function toggleUserStatus(username) {
        const users = JSON.parse(localStorage.getItem('aegis_users')) || [];
        const idx = users.findIndex(u => u.username.toLowerCase() === username.toLowerCase());

        if (idx !== -1) {
            const currentStatus = users[idx].status;
            const newStatus = currentStatus === 'active' ? 'inactive' : 'active';
            users[idx].status = newStatus;

            localStorage.setItem('aegis_users', JSON.stringify(users));

            logActivity(
                currentUser.username, 
                "User Status Toggled", 
                `Changed access state for @${username} from ${currentStatus} to ${newStatus}`
            );

            renderUsers();
        }
    }

    // D. Decommission User Node
    function deleteUser(username) {
        if (!confirm(`Are you sure you want to permanently delete user @${username}?`)) {
            return;
        }

        const users = JSON.parse(localStorage.getItem('aegis_users')) || [];
        const filtered = users.filter(u => u.username.toLowerCase() !== username.toLowerCase());

        localStorage.setItem('aegis_users', JSON.stringify(filtered));

        logActivity(
            currentUser.username, 
            "User Deleted", 
            `Permanently deleted operator account: @${username}`
        );

        renderUsers();
    }

    function closeEditModal() {
        editModal.classList.remove('active');
        editUsernameHidden.value = '';
    }

    // Bind UI actions
    userSearchInput.addEventListener('input', renderUsers);
    closeEditModalBtn.addEventListener('click', closeEditModal);
    closeEditModalBtnFooter.addEventListener('click', closeEditModal);
    
    // Close modal if background is clicked
    editModal.addEventListener('click', (e) => {
        if (e.target === editModal) {
            closeEditModal();
        }
    });

    // Run render on load
    renderUsers();

    // --- Helpers: Header Clock & Sidebar Management ---
    function initCommonElements() {
        // Set user badge inside welcome banner if exists
        const nameSlot = document.getElementById('sessionUsername');
        if (nameSlot) nameSlot.textContent = currentUser.username;

        // Show activity sidebar link for admins
        const menuAct = document.getElementById('menuActivity');
        if (menuAct) menuAct.style.display = 'block';

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
