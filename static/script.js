// Toast notification
function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = 'toast show ' + type;

    setTimeout(() => {
        toast.className = 'toast';
    }, 3000);
}

// Wake on LAN
async function wakeComputer(mac, button) {
    button.disabled = true;
    button.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin">
            <circle cx="12" cy="12" r="10"/>
            <path d="M12 6v6l4 2"/>
        </svg>
        Enviando...
    `;

    try {
        const response = await fetch(`/wake/${mac}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();

        if (data.success) {
            showToast('Pacote Wake-on-LAN enviado!', 'success');
        } else {
            showToast(data.message || 'Erro ao enviar pacote', 'error');
        }
    } catch (error) {
        showToast('Erro de conexao', 'error');
    } finally {
        button.disabled = false;
        button.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <path d="M12 6v6l4 2"/>
            </svg>
            Ligar
        `;
    }
}

// Update status periodically
async function updateStatus() {
    try {
        const response = await fetch('/status');
        const statuses = await response.json();

        document.querySelectorAll('.computer-card').forEach(card => {
            const mac = card.dataset.mac;
            const isOnline = statuses[mac];
            const indicator = card.querySelector('.status-indicator');
            const statusText = card.querySelector('.status-text');

            if (isOnline) {
                indicator.className = 'status-indicator online';
                statusText.textContent = 'Online';
                card.classList.add('online');
            } else {
                indicator.className = 'status-indicator offline';
                statusText.textContent = 'Offline';
                card.classList.remove('online');
            }
        });
    } catch (error) {
        console.error('Erro ao atualizar status:', error);
    }
}

// Add computer form
const addForm = document.getElementById('add-computer-form');
if (addForm) {
    addForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = new FormData(addForm);

        try {
            const response = await fetch('/config/computer', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (data.success) {
                showToast('Computador adicionado!', 'success');
                setTimeout(() => location.reload(), 1000);
            } else {
                showToast(data.message || 'Erro ao adicionar', 'error');
            }
        } catch (error) {
            showToast('Erro de conexao', 'error');
        }
    });
}

// Change own password form
const passwordForm = document.getElementById('change-password-form');
if (passwordForm) {
    passwordForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const current = document.getElementById('current-password').value;
        const newPassword = document.getElementById('new-password').value;

        try {
            const response = await fetch('/profile/password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ current, new: newPassword })
            });

            const data = await response.json();

            if (data.success) {
                showToast('Senha alterada!', 'success');
                passwordForm.reset();
            } else {
                showToast(data.message || 'Erro ao alterar senha', 'error');
            }
        } catch (error) {
            showToast('Erro de conexao', 'error');
        }
    });
}

// Toggle edit mode for computer row
function toggleEdit(button) {
    const row = button.closest('tr');
    const inputs = row.querySelectorAll('input');
    const editBtn = row.querySelector('.btn-edit');
    const saveBtn = row.querySelector('.btn-save');
    const cancelBtn = row.querySelector('.btn-cancel');

    // Store original values
    inputs.forEach(input => {
        input.dataset.original = input.value;
        input.disabled = false;
    });

    editBtn.style.display = 'none';
    saveBtn.style.display = 'inline-flex';
    cancelBtn.style.display = 'inline-flex';
}

// Cancel edit
function cancelEdit(button) {
    const row = button.closest('tr');
    const inputs = row.querySelectorAll('input');
    const editBtn = row.querySelector('.btn-edit');
    const saveBtn = row.querySelector('.btn-save');
    const cancelBtn = row.querySelector('.btn-cancel');

    // Restore original values
    inputs.forEach(input => {
        input.value = input.dataset.original;
        input.disabled = true;
    });

    editBtn.style.display = 'inline-flex';
    saveBtn.style.display = 'none';
    cancelBtn.style.display = 'none';
}

// Save computer
async function saveComputer(button) {
    const row = button.closest('tr');
    const id = row.dataset.id;
    const name = row.querySelector('.edit-name').value;
    const mac = row.querySelector('.edit-mac').value;
    const ip = row.querySelector('.edit-ip').value;

    try {
        const response = await fetch(`/config/computer/${id}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name, mac, ip })
        });

        const data = await response.json();

        if (data.success) {
            showToast('Computador atualizado!', 'success');

            const inputs = row.querySelectorAll('input');
            const editBtn = row.querySelector('.btn-edit');
            const saveBtn = row.querySelector('.btn-save');
            const cancelBtn = row.querySelector('.btn-cancel');

            inputs.forEach(input => input.disabled = true);
            editBtn.style.display = 'inline-flex';
            saveBtn.style.display = 'none';
            cancelBtn.style.display = 'none';
        } else {
            showToast(data.message || 'Erro ao atualizar', 'error');
        }
    } catch (error) {
        showToast('Erro de conexao', 'error');
    }
}

// Delete computer
async function deleteComputer(id) {
    if (!confirm('Tem certeza que deseja excluir este computador?')) {
        return;
    }

    try {
        const response = await fetch(`/config/computer/${id}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (data.success) {
            showToast('Computador removido!', 'success');
            setTimeout(() => location.reload(), 1000);
        } else {
            showToast(data.message || 'Erro ao remover', 'error');
        }
    } catch (error) {
        showToast('Erro de conexao', 'error');
    }
}

// ========== USER MANAGEMENT ==========

// Add user form
const addUserForm = document.getElementById('add-user-form');
if (addUserForm) {
    addUserForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const username = document.getElementById('new-username').value;
        const password = document.getElementById('new-user-password').value;
        const isAdmin = document.getElementById('new-user-admin').checked;

        try {
            const response = await fetch('/config/user', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password, is_admin: isAdmin })
            });

            const data = await response.json();

            if (data.success) {
                showToast('Usuario criado!', 'success');
                setTimeout(() => location.reload(), 1000);
            } else {
                showToast(data.message || 'Erro ao criar usuario', 'error');
            }
        } catch (error) {
            showToast('Erro de conexao', 'error');
        }
    });
}

// Delete user
async function deleteUser(id) {
    if (!confirm('Tem certeza que deseja excluir este usuario?')) {
        return;
    }

    try {
        const response = await fetch(`/config/user/${id}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (data.success) {
            showToast('Usuario removido!', 'success');
            setTimeout(() => location.reload(), 1000);
        } else {
            showToast(data.message || 'Erro ao remover', 'error');
        }
    } catch (error) {
        showToast('Erro de conexao', 'error');
    }
}

// ========== MODALS ==========

function openModal(modalId) {
    document.getElementById(modalId).classList.add('show');
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('show');
}

// Permissions modal
async function openPermissions(computerId, computerName) {
    currentComputerId = computerId;
    document.getElementById('modal-computer-name').textContent = computerName;

    // Build checkboxes for users
    const container = document.getElementById('users-checkboxes');
    container.innerHTML = '';

    // Get current permissions
    let currentUsers = [];
    try {
        const response = await fetch(`/config/computer/${computerId}/users`);
        const data = await response.json();
        if (data.success) {
            currentUsers = data.users;
        }
    } catch (error) {
        console.error('Erro ao carregar permissoes:', error);
    }

    // Create checkboxes (skip admins - they always have access)
    allUsers.filter(u => !u.is_admin).forEach(user => {
        const label = document.createElement('label');
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.value = user.id;
        checkbox.checked = currentUsers.includes(user.id);

        label.appendChild(checkbox);
        label.appendChild(document.createTextNode(user.username));
        container.appendChild(label);
    });

    if (container.children.length === 0) {
        container.innerHTML = '<p style="color: var(--gray);">Nenhum usuario disponivel. Crie usuarios primeiro.</p>';
    }

    openModal('permissions-modal');
}

async function savePermissions() {
    const checkboxes = document.querySelectorAll('#users-checkboxes input[type="checkbox"]:checked');
    const userIds = Array.from(checkboxes).map(cb => parseInt(cb.value));

    try {
        const response = await fetch(`/config/computer/${currentComputerId}/users`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ user_ids: userIds })
        });

        const data = await response.json();

        if (data.success) {
            showToast('Permissoes atualizadas!', 'success');
            closeModal('permissions-modal');
        } else {
            showToast(data.message || 'Erro ao salvar', 'error');
        }
    } catch (error) {
        showToast('Erro de conexao', 'error');
    }
}

// Password modal (admin changing user password)
function openChangePassword(userId, username) {
    currentUserId = userId;
    document.getElementById('modal-user-name').textContent = username;
    document.getElementById('admin-new-password').value = '';
    openModal('password-modal');
}

async function saveUserPassword() {
    const newPassword = document.getElementById('admin-new-password').value;

    if (!newPassword) {
        showToast('Digite a nova senha', 'error');
        return;
    }

    try {
        const response = await fetch(`/config/user/${currentUserId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password: newPassword })
        });

        const data = await response.json();

        if (data.success) {
            showToast('Senha alterada!', 'success');
            closeModal('password-modal');
        } else {
            showToast(data.message || 'Erro ao alterar senha', 'error');
        }
    } catch (error) {
        showToast('Erro de conexao', 'error');
    }
}

// Close modal on outside click
document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.remove('show');
        }
    });
});

// Initialize status polling on dashboard
if (document.querySelector('.computers-grid')) {
    updateStatus();
    setInterval(updateStatus, 10000);
}

// Add spin animation style
const style = document.createElement('style');
style.textContent = `
    @keyframes spin {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }
    .spin {
        animation: spin 1s linear infinite;
    }
`;
document.head.appendChild(style);
