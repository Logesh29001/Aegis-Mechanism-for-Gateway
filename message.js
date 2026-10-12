/**
 * AegisGateway - Secure Messaging Controller
 * Handles sending, inbox loading, and sent log displays.
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Double check authentication
    const user = AegisSession.getCurrentUser();
    if (!user) {
        window.location.href = "login.html";
        return;
    }

    // Set up standard sidebar and clock
    initCommonElements();

    // 2. Determine Page Controller Actions based on DOM element presence
    const messageForm = document.getElementById('messageForm');
    if (messageForm) {
        initMessageComposer(user);
    }

    const inboxTableBody = document.getElementById('inboxTableBody');
    if (inboxTableBody) {
        initInbox(user);
    }

    const sentTableBody = document.getElementById('sentTableBody');
    if (sentTableBody) {
        initSentMessages(user);
    }

    // --- Core Sub-Controllers ---

    // A. Send Message Compose Engine
    function initMessageComposer(currentUser) {
        const receiverSelect = document.getElementById('receiver');
        const subjectInput = document.getElementById('subject');
        const messageInput = document.getElementById('message');
        const fileInput = document.getElementById('attachmentFile');
        const fileStatus = document.getElementById('fileStatus');
        const alertContainer = document.getElementById('alertContainer');

        let isFileValid = true; // Tracks if selected file passes checks
        let fileMetadata = null; // Holds parsed file properties

        // Populate Recipient Dropdown list
        const users = JSON.parse(localStorage.getItem('aegis_users')) || [];
        const eligibleRecipients = users.filter(u => u.username.toLowerCase() !== currentUser.username.toLowerCase());
        
        eligibleRecipients.forEach(rec => {
            const option = document.createElement('option');
            option.value = rec.username;
            const safeFullName = SecurityGuard.escapeHTML(rec.fullName);
            const safeUsername = SecurityGuard.escapeHTML(rec.username);
            option.textContent = `${safeFullName} (@${safeUsername}) [${rec.role}]`;
            receiverSelect.appendChild(option);
        });

        // Whitelists for file validation
        const allowedExtensions = ['txt', 'pdf', 'png', 'jpg', 'jpeg', 'bin'];
        const allowedMimeTypes = [
            'text/plain', 
            'application/pdf', 
            'image/png', 
            'image/jpeg', 
            'application/octet-stream' // common for .bin files
        ];
        const maxSizeBytes = 2 * 1024 * 1024; // 2MB limit

        // File Selection listener - performs metadata validations
        fileInput.addEventListener('change', () => {
            fileStatus.className = 'input-status';
            fileStatus.innerHTML = '';
            isFileValid = true;
            fileMetadata = null;

            if (fileInput.files.length === 0) return;

            const file = fileInput.files[0];
            const extension = file.name.split('.').pop().toLowerCase();
            const sizeMB = (file.size / (1024 * 1024)).toFixed(2);

            // Validation 1: Size limits check (Max 2MB)
            if (file.size > maxSizeBytes) {
                fileStatus.textContent = `Rejected: File is too large (${sizeMB} MB). Max allowed size is 2.00 MB.`;
                fileStatus.className = 'input-status active status-invalid';
                isFileValid = false;
                return;
            }

            // Validation 2: Extension whitelist check
            if (!allowedExtensions.includes(extension)) {
                fileStatus.textContent = `Rejected: File extension ".${extension}" is blocked.`;
                fileStatus.className = 'input-status active status-invalid';
                isFileValid = false;
                return;
            }

            // Validation 3: MIME type checks
            const mimeTypeMatched = allowedMimeTypes.some(type => {
                if (type === file.type) return true;
                // If extension is bin and MIME is missing, bypass (common browser behavior for custom binary files)
                if (extension === 'bin' && !file.type) return true;
                return false;
            });

            if (!mimeTypeMatched) {
                fileStatus.textContent = `Rejected: Detected invalid file type (${file.type || 'unknown MIME'}).`;
                fileStatus.className = 'input-status active status-invalid';
                isFileValid = false;
                return;
            }

            // If all checks pass, configure metadata parameters
            fileMetadata = {
                name: file.name,
                size: file.size,
                type: file.type,
                rawFile: file // Keep reference to read on submit
            };

            fileStatus.textContent = `Verified: File format checks passed (${file.name} - ${(file.size/1024).toFixed(1)} KB)`;
            fileStatus.className = 'input-status active status-valid';
        });

        // Helper: Convert File object to Base64 string asynchronously
        function readFileAsBase64(fileObj) {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = () => resolve(reader.result);
                reader.onerror = (err) => reject(err);
                reader.readAsDataURL(fileObj);
            });
        }

        // Form Submission validation & dispatch write
        messageForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const receiver = receiverSelect.value;
            const subject = subjectInput.value.trim();
            const message = messageInput.value.trim();

            alertContainer.innerHTML = '';

            // Validation Checks
            if (!receiver) {
                displayAlert("Transmission aborted. Please select a recipient node.", "danger");
                return;
            }
            if (!subject || !message) {
                displayAlert("Transmission aborted. Subject and message payload cannot be empty.", "danger");
                return;
            }

            // If file was selected but did not pass verification checks, abort submission
            if (fileInput.files.length > 0 && !isFileValid) {
                displayAlert("Transmission aborted. Attachment file contains format violations.", "danger");
                return;
            }

            const uniqueId = "MSG-" + Date.now().toString(36).toUpperCase() + "-" + Math.random().toString(36).substring(2, 7).toUpperCase();

            // Structure outbound schema
            const newMessage = {
                id: uniqueId,
                sender: currentUser.username,
                receiver: receiver,
                subject: subject,
                message: message,
                attachmentName: fileMetadata ? fileMetadata.name : null,
                attachmentData: null, // Holds Base64 data URL if applicable
                date: new Date().toISOString(),
                status: "unread"
            };

            // Read attachment data if valid file exists
            if (fileMetadata) {
                const file = fileMetadata.rawFile;
                // Performance safeguard: Convert and save file contents only if file is <= 100KB.
                // For files larger than 100KB (up to 2MB limits), we store only filename metadata
                // to prevent exceeding browser LocalStorage capacity constraints.
                if (file.size <= 100 * 1024) {
                    try {
                        newMessage.attachmentData = await readFileAsBase64(file);
                    } catch (err) {
                        console.error("FileReader failed:", err);
                        displayAlert("Warning: Failed to ingest attachment data. Transmitting without contents.", "warning");
                    }
                } else {
                    newMessage.attachmentData = "metadata_verified";
                }
            }

            try {
                // Save to database
                const messages = JSON.parse(localStorage.getItem('aegis_messages')) || [];
                messages.push(newMessage);
                localStorage.setItem('aegis_messages', JSON.stringify(messages));

                // Log Activity
                logActivity(
                    currentUser.username, 
                    "Message Transmitted", 
                    `Secure dispatch sent to: @${receiver} (ID: ${uniqueId})` + 
                    (fileMetadata ? ` with attachment: ${fileMetadata.name}` : '')
                );

                displayAlert(`Dispatch packets transmitted successfully. Identifier: ${uniqueId}`, "success");
                
                // Clear fields
                messageForm.reset();
                fileStatus.className = 'input-status';
                fileStatus.innerHTML = '';
                isFileValid = true;
                fileMetadata = null;
            } catch (err) {
                console.error("Storage write error:", err);
                displayAlert("System Storage Full. Transmission failed.", "danger");
            }
        });

        function displayAlert(messageText, type) {
            alertContainer.innerHTML = '';
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert-popup alert-popup-${type}`;
            const safeText = SecurityGuard.escapeHTML(messageText);
            alertDiv.innerHTML = `<span><strong>AEGIS GUARD:</strong> ${safeText}</span>`;
            alertContainer.appendChild(alertDiv);
        }
    }

    // B. Received Messages Inbox Engine
    function initInbox(currentUser) {
        const searchQuery = document.getElementById('searchQuery');
        const statusFilter = document.getElementById('statusFilter');
        const modal = document.getElementById('messageModalOverlay');
        
        const modalSubject = document.getElementById('modalSubject');
        const modalSender = document.getElementById('modalSender');
        const modalDate = document.getElementById('modalDate');
        const modalMessage = document.getElementById('modalMessage');
        const modalAttachment = document.getElementById('modalAttachment');
        
        const closeModalBtn = document.getElementById('closeModalBtn');
        const closeModalBtnFooter = document.getElementById('closeModalBtnFooter');
        const deleteModalBtn = document.getElementById('deleteModalBtn');

        let activeMessageId = null;

        function renderInbox() {
            const messages = JSON.parse(localStorage.getItem('aegis_messages')) || [];
            let inboxList = messages.filter(m => m.receiver.toLowerCase() === currentUser.username.toLowerCase());

            const statusVal = statusFilter.value;
            if (statusVal === 'unread') {
                inboxList = inboxList.filter(m => m.status === 'unread');
            } else if (statusVal === 'read') {
                inboxList = inboxList.filter(m => m.status === 'read');
            }

            const query = searchQuery.value.trim().toLowerCase();
            if (query.length > 0) {
                inboxList = inboxList.filter(m => 
                    m.sender.toLowerCase().includes(query) ||
                    m.subject.toLowerCase().includes(query) ||
                    m.message.toLowerCase().includes(query)
                );
            }

            inboxList.sort((a, b) => new Date(b.date) - new Date(a.date));
            inboxTableBody.innerHTML = '';

            if (inboxList.length === 0) {
                inboxTableBody.innerHTML = `
                    <tr>
                        <td colspan="5" style="text-align: center; color: var(--text-muted);">
                            No incoming transmissions found.
                        </td>
                    </tr>
                `;
                return;
            }

            inboxList.forEach(msg => {
                const tr = document.createElement('tr');
                if (msg.status === 'unread') {
                    tr.className = 'msg-row-unread';
                }

                const dateStr = new Date(msg.date).toLocaleString();
                const safeSender = SecurityGuard.escapeHTML(msg.sender);
                const safeSubject = SecurityGuard.escapeHTML(msg.subject);
                const statusBadge = msg.status === 'unread' 
                    ? '<span class="status-badge status-unread">unread</span>' 
                    : '<span class="status-badge status-read">read</span>';

                tr.innerHTML = `
                    <td>@${safeSender}</td>
                    <td>${safeSubject}</td>
                    <td style="font-family: var(--font-mono); font-size: 0.8rem;">${dateStr}</td>
                    <td>${statusBadge}</td>
                    <td>
                        <button class="btn btn-primary btn-sm view-btn" style="padding: 2px 6px;">Open</button>
                        <button class="btn btn-secondary btn-sm delete-btn" style="padding: 2px 6px; border-color: var(--color-danger); color: var(--color-danger); margin-left: 5px;">Del</button>
                    </td>
                `;

                tr.addEventListener('click', (e) => {
                    if (e.target.classList.contains('delete-btn')) {
                        deleteMessage(msg.id);
                    } else {
                        openMessage(msg);
                    }
                });

                inboxTableBody.appendChild(tr);
            });
        }

        function openMessage(msg) {
            activeMessageId = msg.id;
            modalSubject.textContent = msg.subject;
            modalSender.textContent = `@${msg.sender}`;
            modalDate.textContent = new Date(msg.date).toLocaleString();
            modalMessage.textContent = msg.message;

            // Decryption Attachment Rendering with Dynamic Downloads
            if (msg.attachmentName) {
                const safeAttachment = SecurityGuard.escapeHTML(msg.attachmentName);
                if (msg.attachmentData && msg.attachmentData.startsWith('data:')) {
                    // Ingested Base64 content: expose download link
                    modalAttachment.innerHTML = `
                        📎 Attachment: <strong style="color: var(--accent-secondary);">${safeAttachment}</strong><br>
                        <a href="${msg.attachmentData}" download="${msg.attachmentName}" class="btn btn-primary btn-sm" style="margin-top: 8px; font-size:0.75rem; padding: 4px 10px;">Download Decrypted File</a>
                    `;
                } else {
                    // Mock/Withheld content
                    modalAttachment.innerHTML = `
                        📎 Attachment: <strong style="color: var(--color-warning);">${safeAttachment}</strong>
                        <span style="font-size:0.75rem; color:var(--text-muted);">(Metadata verified. Content larger than 100KB is withheld)</span>
                    `;
                }
            } else {
                modalAttachment.innerHTML = '';
            }

            modal.classList.add('active');

            if (msg.status === 'unread') {
                const messages = JSON.parse(localStorage.getItem('aegis_messages')) || [];
                const matchedIdx = messages.findIndex(m => m.id === msg.id);
                if (matchedIdx !== -1) {
                    messages[matchedIdx].status = 'read';
                    localStorage.setItem('aegis_messages', JSON.stringify(messages));
                    
                    logActivity(
                        currentUser.username, 
                        "Message Decrypted", 
                        `Read message ID: ${msg.id} sent by: @${msg.sender}`
                    );
                    renderInbox();
                }
            }
        }

        function deleteMessage(msgId) {
            if (!confirm("Are you sure you want to delete this secure transmission?")) {
                return;
            }

            const messages = JSON.parse(localStorage.getItem('aegis_messages')) || [];
            const updatedMessages = messages.filter(m => m.id !== msgId);
            localStorage.setItem('aegis_messages', JSON.stringify(updatedMessages));

            logActivity(
                currentUser.username, 
                "Message Deleted", 
                `Deleted secure message record ID: ${msgId}`
            );

            closeModal();
            renderInbox();
        }

        function closeModal() {
            modal.classList.remove('active');
            activeMessageId = null;
        }

        searchQuery.addEventListener('input', renderInbox);
        statusFilter.addEventListener('change', renderInbox);
        closeModalBtn.addEventListener('click', closeModal);
        closeModalBtnFooter.addEventListener('click', closeModal);
        deleteModalBtn.addEventListener('click', () => {
            if (activeMessageId) {
                deleteMessage(activeMessageId);
            }
        });

        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeModal();
            }
        });

        renderInbox();
    }

    // C. Sent Messages Log Engine
    function initSentMessages(currentUser) {
        const searchQuery = document.getElementById('searchQuery');
        const statusFilter = document.getElementById('statusFilter');
        const modal = document.getElementById('messageModalOverlay');
        
        const modalSubject = document.getElementById('modalSubject');
        const modalReceiver = document.getElementById('modalReceiver');
        const modalDate = document.getElementById('modalDate');
        const modalMessage = document.getElementById('modalMessage');
        const modalAttachment = document.getElementById('modalAttachment');
        
        const closeModalBtn = document.getElementById('closeModalBtn');
        const closeModalBtnFooter = document.getElementById('closeModalBtnFooter');
        const deleteModalBtn = document.getElementById('deleteModalBtn');

        let activeMessageId = null;

        function renderSent() {
            const messages = JSON.parse(localStorage.getItem('aegis_messages')) || [];
            let sentList = messages.filter(m => m.sender.toLowerCase() === currentUser.username.toLowerCase());

            const statusVal = statusFilter.value;
            if (statusVal === 'unread') {
                sentList = sentList.filter(m => m.status === 'unread');
            } else if (statusVal === 'read') {
                sentList = sentList.filter(m => m.status === 'read');
            }

            const query = searchQuery.value.trim().toLowerCase();
            if (query.length > 0) {
                sentList = sentList.filter(m => 
                    m.receiver.toLowerCase().includes(query) ||
                    m.subject.toLowerCase().includes(query) ||
                    m.message.toLowerCase().includes(query)
                );
            }

            sentList.sort((a, b) => new Date(b.date) - new Date(a.date));
            sentTableBody.innerHTML = '';

            if (sentList.length === 0) {
                sentTableBody.innerHTML = `
                    <tr>
                        <td colspan="5" style="text-align: center; color: var(--text-muted);">
                            No outbound transmissions found.
                        </td>
                    </tr>
                `;
                return;
            }

            sentList.forEach(msg => {
                const tr = document.createElement('tr');
                const dateStr = new Date(msg.date).toLocaleString();
                const safeReceiver = SecurityGuard.escapeHTML(msg.receiver);
                const safeSubject = SecurityGuard.escapeHTML(msg.subject);
                const statusBadge = msg.status === 'unread' 
                    ? '<span class="status-badge status-unread">delivered</span>' 
                    : '<span class="status-badge status-read">opened</span>';

                tr.innerHTML = `
                    <td>@${safeReceiver}</td>
                    <td>${safeSubject}</td>
                    <td style="font-family: var(--font-mono); font-size: 0.8rem;">${dateStr}</td>
                    <td>${statusBadge}</td>
                    <td>
                        <button class="btn btn-primary btn-sm view-btn" style="padding: 2px 6px;">Open</button>
                        <button class="btn btn-secondary btn-sm delete-btn" style="padding: 2px 6px; border-color: var(--color-danger); color: var(--color-danger); margin-left: 5px;">Del</button>
                    </td>
                `;

                tr.addEventListener('click', (e) => {
                    if (e.target.classList.contains('delete-btn')) {
                        deleteSentMessage(msg.id);
                    } else {
                        openSentMessage(msg);
                    }
                });

                sentTableBody.appendChild(tr);
            });
        }

        function openSentMessage(msg) {
            activeMessageId = msg.id;
            modalSubject.textContent = msg.subject;
            modalReceiver.textContent = `@${msg.receiver}`;
            modalDate.textContent = new Date(msg.date).toLocaleString();
            modalMessage.textContent = msg.message;

            // Decryption Attachment Rendering with Dynamic Downloads
            if (msg.attachmentName) {
                const safeAttachment = SecurityGuard.escapeHTML(msg.attachmentName);
                if (msg.attachmentData && msg.attachmentData.startsWith('data:')) {
                    modalAttachment.innerHTML = `
                        📎 Attachment: <strong style="color: var(--accent-secondary);">${safeAttachment}</strong><br>
                        <a href="${msg.attachmentData}" download="${msg.attachmentName}" class="btn btn-primary btn-sm" style="margin-top: 8px; font-size:0.75rem; padding: 4px 10px;">Download Decrypted File</a>
                    `;
                } else {
                    modalAttachment.innerHTML = `
                        📎 Attachment: <strong style="color: var(--color-warning);">${safeAttachment}</strong>
                        <span style="font-size:0.75rem; color:var(--text-muted);">(Metadata verified. Content larger than 100KB is withheld)</span>
                    `;
                }
            } else {
                modalAttachment.innerHTML = '';
            }

            modal.classList.add('active');
        }

        function deleteSentMessage(msgId) {
            if (!confirm("Are you sure you want to delete this transmission record from your log?")) {
                return;
            }

            const messages = JSON.parse(localStorage.getItem('aegis_messages')) || [];
            const updatedMessages = messages.filter(m => m.id !== msgId);
            localStorage.setItem('aegis_messages', JSON.stringify(updatedMessages));

            logActivity(
                currentUser.username, 
                "Outbound Log Deleted", 
                `Deleted sent message record ID: ${msgId}`
            );

            closeModal();
            renderSent();
        }

        function closeModal() {
            modal.classList.remove('active');
            activeMessageId = null;
        }

        searchQuery.addEventListener('input', renderSent);
        statusFilter.addEventListener('change', renderSent);
        closeModalBtn.addEventListener('click', closeModal);
        closeModalBtnFooter.addEventListener('click', closeModal);
        deleteModalBtn.addEventListener('click', () => {
            if (activeMessageId) {
                deleteSentMessage(activeMessageId);
            }
        });

        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeModal();
            }
        });

        renderSent();
    }

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
