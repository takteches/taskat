// ****************************************************************************************************
// ****************************************************************************************************
// **                                                                                              **
// **                            🚨 CRITICAL SECURITY WARNING 🚨                                   **
// **                                                                                              **
// ** This client-side approach is FUNDAMENTALLY INSECURE for production use.                      **
// ** API keys and sensitive data are visible to anyone who inspects the source code.              **
// **                                                                                              **
// ** FOR PRODUCTION: Implement a secure backend server to handle all API calls                    **
// ** and store sensitive credentials server-side only.                                            **
// **                                                                                              **
// ** Current implementation is for DEVELOPMENT/DEMO purposes ONLY.                                **
// **                                                                                              **
// ****************************************************************************************************
// ****************************************************************************************************

// Enhanced configuration with multiple layers of obfuscation
const _config = (() => {
    const parts = ['19pWWNEBYlep9VU6gT', 'cYDknYzzrefKoN'];
    // Reverted to original obfuscated base URL
    const base = 'aHR0cHM6Ly9hcGkuYmFzZXJvdy5pby9hcGkvZGF0YWJhc2Uvcm93cy90YWJsZS8=';

    return {
        getKey: () => parts.join(''),
        getBase: () => atob(base), // Decode the base URL
        dbId: '276777',
        tables: {
            u: '647091', // User table ID (still here for reference, but not used for loading users)
            t: '647088'  // Task table ID
        }
    };
})();

// Enhanced password hashing with multiple rounds
const createSecureHash = (password, salt = 'taskapp2024') => {
    let hash = password + salt;
    for (let i = 0; i < 1000; i++) {
        hash = CryptoJS.SHA256(hash).toString();
    }
    return hash;
};

// Admin credentials - heavily obfuscated
const ADMIN_CONFIG = (() => {
    const u = atob('YWRtaW4='); // 'admin'
    const h = createSecureHash(atob('YWRtaW4xMjM=')); // 'admin123'
    return { u, h };
})();

// Global state management with enhanced security
let appState = {
    currentUser: null,
    allTasks: [],
    users: [],
    filteredTasks: [],
    debugMode: false, // Set to false by default
    availableFields: [],
    userFields: [],
    currentDetailTaskId: null,
    activeTab: 'active',
    taskIdToComplete: null,
    securityLevel: 'high',
    currentViewMode: 'grid' // Added for view mode toggle
};

// Enhanced input validation with XSS protection
const validateInput = (input, type = 'text', maxLength = 255) => {
    if (!input || typeof input !== 'string') return '';

    // Enhanced XSS prevention
    const sanitized = input
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
        .replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, '')
        .replace(/<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .replace(/<[^>]*>/g, '')
        .trim()
        .substring(0, maxLength);

    switch (type) {
        case 'username':
            return sanitized.replace(/[^a-zA-Z0-9_-]/g, '');
        case 'email':
            return sanitized.toLowerCase();
        case 'date':
            return sanitized.match(/^\d{4}-\d{2}-\d{2}$/) ? sanitized : '';
        default:
            return sanitized;
    }
};

// Secure API client with enhanced protection
class SecureApiClient {
    constructor() {
        this.requestCount = 0;
        this.lastRequestTime = 0;
        this.rateLimitDelay = 300; // Increased delay
    }

    async makeRequest(endpoint, options = {}) {
        // Rate limiting with increased delay
        const now = Date.now();
        const timeSinceLastRequest = now - this.lastRequestTime;
        if (timeSinceLastRequest < this.rateLimitDelay) {
            await new Promise(resolve => setTimeout(resolve, this.rateLimitDelay - timeSinceLastRequest));
        }

        this.lastRequestTime = Date.now();
        this.requestCount++;

        const headers = {
            'Authorization': `Token ${_config.getKey()}`,
            'Content-Type': 'application/json',
            ...options.headers
        };

        try {
            const response = await fetch(endpoint, {
                ...options,
                headers
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Request failed: ${response.status} - ${errorText}`);
            }

            return response;
        } catch (error) {
            console.error('API Request failed:', error);
            throw error;
        }
    }
}

const apiClient = new SecureApiClient();

// Initialize application with enhanced security
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

async function initializeApp() {
    try {
        showNotification('Initializing application...', 'info');
        // --- MODIFIED: Load users from JSON file instead of Baserow API ---
        await loadUsersFromJson(); // Call the new function
        // --- END MODIFIED ---
        setupEventListeners();
        checkSavedLogin();
        showNotification('Application initialized successfully', 'success');
    } catch (error) {
        showNotification('Failed to initialize application', 'error');
        console.error('Initialization error:', error);
    }
}

// --- NEW FUNCTION: Load users from a JSON file hosted on GitHub ---
async function loadUsersFromJson() {
    try {
        // IMPORTANT: Replace with the RAW URL to your users.json file on GitHub.
        // Example: https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/YOUR_REPO_NAME/main/data/users.json
        const jsonUrl = 'https://raw.githubusercontent.com/takteches/taskat/main/users.json'; 
        console.log("Hash for '112233':", createSecureHash('112233'));

        const response = await fetch(jsonUrl);
        if (!response.ok) {
            throw new Error(`Failed to load users JSON: ${response.status} - ${response.statusText}`);
        }
        const usersData = await response.json();

        if (Array.isArray(usersData) && usersData.length > 0) {
            const processedUsers = usersData.map(user => ({
                Id: user.username, // Using username as Id for simplicity in JSON
                username: validateInput(user.username, 'username'),
                password: user.passwordHash, // Password is assumed to be pre-hashed in the JSON
                role: validateInput(user.role || 'user').toLowerCase(),
                fullName: validateInput(user.fullName || user.username)
            }));
            appState.users = processedUsers;
            showNotification(`Loaded ${processedUsers.length} users from JSON file.`, 'success');
        } else {
            throw new Error('No users found in JSON file or invalid format.');
        }

    } catch (error) {
        console.error('Error loading users from JSON:', error);
        appState.users = [];
        showNotification('Failed to load users from JSON file. Please check the file and URL.', 'error');
    }
}
// --- END NEW FUNCTION ---
console.log("Hash for '112233':", createSecureHash('112233'));
// Enhanced task loading with data protection and pagination (still uses Baserow)
async function loadTasks() {
    document.getElementById('loadingSpinner').classList.remove('hidden');
    document.getElementById('tasksContainer').innerHTML = '';
    document.getElementById('tasksListContainer').innerHTML = ''; // Clear list container too

    try {
        let allTasks = [];
        let nextUrl = `${_config.getBase()}${_config.tables.t}/?user_field_names=true`;

        while (nextUrl) {
            const response = await apiClient.makeRequest(nextUrl);
            const data = await response.json();

            if (data.results && data.results.length > 0) {
                // Only set availableFields once from the first response
                if (allTasks.length === 0) {
                    appState.availableFields = Object.keys(data.results[0]);
                }

                // Process tasks with enhanced security
                const processedTasks = [];
                for (const record of data.results) {
                    processedTasks.push({
                        Id: String(record.id || record.Id),
                        title: validateInput(record.Title || record.title || '', 'text', 200),
                        description: validateInput(record.Description || record.description || '', 'text', 1000),
                        branch: validateInput(record.Branch || record.branch || ''),
                        priority: validateInput(record.Priority || record.priority || ''),
                        assignee: validateInput(record.Assignee || record.assignee || ''),
                        dueDate: validateInput(record['Due Date'] || record.DueDate || '', 'date'),
                        status: validateInput(record.Status || record.status || 'Pending'),
                        userNote: validateInput(record['User Note'] || record.UserNote || '', 'text', 500),
                        createdAt: record.created_at || record.Created_At || new Date().toISOString() // Add created at
                    });
                }
                allTasks.push(...processedTasks); // Add processed tasks to the main array
                nextUrl = data.next; // Get the URL for the next page
            } else {
                nextUrl = null; // No more results
            }
        }

        if (allTasks.length > 0) {
            appState.allTasks = allTasks;
            showNotification(`Loaded ${allTasks.length} tasks from Baserow.`, 'success');
        } else {
            throw new Error('No tasks found from Baserow.');
        }

    } catch (error) {
        console.error('Error loading tasks from Baserow:', error);
        showNotification('Failed to load tasks from Baserow. Please check Baserow configuration.', 'error');
        appState.allTasks = []; // Ensure tasks array is empty if loading fails
    }

    document.getElementById('loadingSpinner').classList.add('hidden');
    filterTasks();
    updateStats();
    renderTasks();
    populateFilters();
}

// Enhanced authentication
function handleLogin(e) {
    e.preventDefault();

    const username = validateInput(document.getElementById('username').value, 'username');
    const password = validateInput(document.getElementById('password').value);

    if (!username || !password) {
        showLoginError('Please enter valid credentials');
        return;
    }

    // Check admin credentials
    if (username === ADMIN_CONFIG.u && createSecureHash(password) === ADMIN_CONFIG.h) {
        appState.currentUser = { username: 'admin', role: 'admin', fullName: 'Administrator' };
        sessionStorage.setItem('currentUser', JSON.stringify({
            username: 'admin',
            role: 'admin',
            fullName: 'Administrator'
        }));
        showDashboard();
        showNotification('Welcome Administrator!', 'success');
        return;
    }

    // Check regular user credentials
    const hashedPassword = createSecureHash(password);
    // For JSON users, the password in appState.users is already hashed
    const user = appState.users.find(u => u.username === username && u.password === hashedPassword);

    if (user) {
        const sessionUser = {
            username: user.username,
            role: user.role,
            fullName: user.fullName,
            Id: user.Id
        };
        appState.currentUser = user;
        sessionStorage.setItem('currentUser', JSON.stringify(sessionUser));
        showDashboard();
        showNotification(`Welcome ${user.fullName}!`, 'success');
    } else {
        showLoginError('Invalid username or password');
    }

    // Clear form immediately after login attempt
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
}

function showLoginError(message) {
    const errorElement = document.getElementById('loginError');
    errorElement.textContent = message;
    errorElement.classList.remove('hidden');
    setTimeout(() => errorElement.classList.add('hidden'), 3000);
}

// Enhanced task filtering
function filterTasks() {
    let tempFilteredTasks = appState.allTasks;

    if (appState.currentUser && appState.currentUser.role !== 'admin') {
        const username = appState.currentUser.username;
        const existingBranches = [...new Set(appState.allTasks.map(task => task.branch).filter(b => b))];
        const isBranchUser = existingBranches.includes(username);

        if (isBranchUser) {
            tempFilteredTasks = tempFilteredTasks.filter(task => task.branch === username);
        } else {
            tempFilteredTasks = tempFilteredTasks.filter(task =>
                task.assignee === appState.currentUser.fullName ||
                task.assignee === appState.currentUser.username
            );
        }
    } else if (appState.currentUser && appState.currentUser.role === 'admin') {
        const branchFilter = document.getElementById('branchFilter').value;
        const userFilter = document.getElementById('userFilter').value;
        const statusFilter = document.getElementById('statusFilter').value;
        const priorityFilter = document.getElementById('priorityFilter').value;

        tempFilteredTasks = appState.allTasks.filter(task => {
            if (branchFilter && task.branch !== branchFilter) return false;
            if (userFilter && task.assignee !== userFilter) return false;
            if (statusFilter) {
                if (statusFilter === 'Overdue') {
                    if (task.status === 'Completed' || new Date(task.dueDate) >= new Date()) return false;
                } else if (task.status !== statusFilter) {
                    return false;
                }
            }
            if (priorityFilter && task.priority !== priorityFilter) return false;
            return true;
        });
    }

    appState.filteredTasks = tempFilteredTasks;
    updateStats();
    renderTasks();
    updateFilterSummary();
}

// Enhanced task saving
async function saveTask() {
    const saveBtn = document.getElementById('saveTaskBtn');
    const saveText = document.getElementById('saveTaskText');
    const saveSpinner = document.getElementById('saveTaskSpinner');

    saveBtn.disabled = true;
    saveText.textContent = 'Saving...';
    saveSpinner.classList.remove('hidden');

    try {
        const taskId = document.getElementById('taskId').value;
        const isEdit = taskId; // Simplified check

        const title = validateInput(document.getElementById('taskTitle').value, 'text', 200);
        const description = validateInput(document.getElementById('taskDescription').value, 'text', 1000);

        if (!title.trim()) {
            throw new Error('Task title is required');
        }

        if (isEdit) {
            await updateExistingTask(taskId);
        } else {
            if (appState.currentUser.role !== 'admin') {
                throw new Error('Only administrators can create new tasks');
            }
            await createNewTasks();
        }

        closeTaskModal();
        filterTasks();

    } catch (error) {
        showNotification(`Failed to save task: ${error.message}`, 'error');
    } finally {
        saveBtn.disabled = false;
        saveText.textContent = 'Save Task';
        saveSpinner.classList.add('hidden');
    }
}

async function updateExistingTask(taskId) {
    const existingTask = appState.allTasks.find(t => String(t.Id) === String(taskId));
    if (!existingTask) {
        throw new Error('Task not found for update');
    }

    let taskData = {};
    if (appState.currentUser.role === 'admin') {
        taskData = getValidatedTaskData();
    } else {
        taskData['Status'] = validateInput(document.getElementById('taskStatus').value);
        taskData['User Note'] = validateInput(document.getElementById('taskUserNote').value, 'text', 500);
    }

    const url = `${_config.getBase()}${_config.tables.t}/${taskId}/?user_field_names=true`;
    const response = await apiClient.makeRequest(url, {
        method: 'PATCH',
        body: JSON.stringify(taskData)
    });

    const updatedRecord = await response.json();

    const taskIndex = appState.allTasks.findIndex(t => String(t.Id) === String(taskId));
    if (taskIndex !== -1) {
        appState.allTasks[taskIndex] = {
            Id: String(updatedRecord.id || updatedRecord.Id),
            title: validateInput(updatedRecord.Title || ''),
            description: validateInput(updatedRecord.Description || ''),
            branch: validateInput(updatedRecord.Branch || ''),
            priority: validateInput(updatedRecord.Priority || ''),
            assignee: validateInput(updatedRecord.Assignee || ''),
            dueDate: validateInput(updatedRecord['Due Date'] || '', 'date'),
            status: validateInput(updatedRecord.Status || 'Pending'),
            userNote: validateInput(updatedRecord['User Note'] || '', 'text', 500),
            createdAt: updatedRecord.created_at || updatedRecord.Created_At || appState.allTasks[taskIndex].createdAt
        };
    }

    showNotification('Task updated successfully!', 'success');
}

function getValidatedTaskData() {
    return {
        'Title': validateInput(document.getElementById('taskTitle').value, 'text', 200),
        'Description': validateInput(document.getElementById('taskDescription').value, 'text', 1000),
        'Branch': validateInput(document.getElementById('taskBranch').value),
        'Priority': validateInput(document.getElementById('taskPriority').value),
        'Assignee': validateInput(document.getElementById('taskAssignee') ? document.getElementById('taskAssignee').value : appState.currentUser.fullName || appState.currentUser.username),
        'Due Date': validateInput(document.getElementById('taskDueDate').value, 'date'),
        'Status': validateInput(document.getElementById('taskStatus').value),
        'User Note': validateInput(document.getElementById('taskUserNote').value, 'text', 500)
    };
}

function normalizeTaskId(id) {
    return String(id);
}

function findTaskById(taskId) {
    const normalizedId = normalizeTaskId(taskId);
    return appState.allTasks.find(t => normalizeTaskId(t.Id) === normalizedId);
}

function setupEventListeners() {
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    // Add event listeners for view mode buttons
    const gridViewBtn = document.getElementById('gridViewBtn');
    const listViewBtn = document.getElementById('listViewBtn');
    if (gridViewBtn) gridViewBtn.addEventListener('click', () => setViewMode('grid'));
    if (listViewBtn) listViewBtn.addEventListener('click', () => setViewMode('list'));
}

function checkSavedLogin() {
    const savedUser = sessionStorage.getItem('currentUser');
    if (savedUser) {
        try {
            const sessionUser = JSON.parse(savedUser);
            const fullUser = appState.users.find(u => u.username === sessionUser.username);
            if (fullUser) {
                appState.currentUser = fullUser;
                showDashboard();
                showNotification(`Welcome back, ${fullUser.fullName}!`, 'info');
            } else {
                sessionStorage.removeItem('currentUser');
            }
        } catch (e) {
            sessionStorage.removeItem('currentUser');
        }
    }
}

function showDashboard() {
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('dashboard').classList.remove('hidden');

    document.getElementById('userWelcome').textContent = `Welcome, ${appState.currentUser.fullName}!`;
    document.getElementById('userRole').textContent = `Role: ${appState.currentUser.role}`;

    const adminControls = document.getElementById('adminControls');
    const filterControls = document.getElementById('filterControls');
    const userTabs = document.getElementById('userTabs');
    const viewModeControls = document.getElementById('viewModeControls'); // Get view mode controls

    if (appState.currentUser.role === 'admin') {
        adminControls.classList.remove('hidden');
        filterControls.classList.remove('hidden');
        userTabs.classList.add('hidden');
        viewModeControls.classList.add('hidden'); // Hide view mode controls for admin

        // Admin always uses list view
        document.getElementById('tasksContainer').classList.add('hidden'); // Hide grid for admin
        document.getElementById('tasksListContainer').classList.remove('hidden'); // Show list for admin

        ['branchFilter', 'userFilter', 'statusFilter', 'priorityFilter'].forEach(id => {
            document.getElementById(id).addEventListener('change', filterTasks);
        });
    } else {
        adminControls.classList.add('hidden');
        filterControls.classList.add('hidden');
        userTabs.classList.remove('hidden');
        viewModeControls.classList.remove('hidden'); // Show view mode controls for user

        // Default to grid view for users, but allow toggle
        document.getElementById('tasksContainer').classList.remove('hidden');
        document.getElementById('tasksListContainer').classList.add('hidden');
        setViewMode('grid'); // Ensure user starts in grid view
    }

    loadTasks();
}

function logout() {
    appState.currentUser = null;
    appState.allTasks = [];
    appState.filteredTasks = [];
    sessionStorage.clear();

    document.getElementById('dashboard').classList.add('hidden');
    document.getElementById('loginScreen').classList.remove('hidden');
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    showNotification('Logged out successfully', 'info');
}

function updateStats() {
    let tasksToCount = [];

    if (appState.currentUser && appState.currentUser.role === 'admin') {
        tasksToCount = appState.filteredTasks;
    } else {
        const username = appState.currentUser.username;
        const existingBranches = [...new Set(appState.allTasks.map(task => task.branch).filter(b => b))];
        const isBranchUser = existingBranches.includes(username);

        if (isBranchUser) {
            tasksToCount = appState.allTasks.filter(task => task.branch === username);
        } else {
            tasksToCount = appState.allTasks.filter(task =>
                task.assignee === appState.currentUser.fullName ||
                task.assignee === appState.currentUser.username
            );
        }
    }

    const total = tasksToCount.length;
    const pending = tasksToCount.filter(task => task.status === 'Pending').length;
    const completed = tasksToCount.filter(task => task.status === 'Completed').length;
    const overdue = tasksToCount.filter(task =>
        task.status !== 'Completed' && new Date(task.dueDate) < new Date()
    ).length;

    document.getElementById('totalTasks').textContent = total;
    document.getElementById('pendingTasks').textContent = pending;
    document.getElementById('completedTasks').textContent = completed;
    document.getElementById('overdueTasks').textContent = overdue;
}

// NEW: Group tasks by title for admin summary view
function groupTasksByTitle(tasks) {
    const grouped = {};
    
    tasks.forEach(task => {
        const key = task.title;
        if (!grouped[key]) {
            grouped[key] = {
                title: task.title,
                description: task.description,
                priority: task.priority,
                dueDate: task.dueDate,
                createdAt: task.createdAt, // Add createdAt to grouped data
                tasks: [],
                totalBranches: 0,
                completedBranches: 0
            };
        }
        
        grouped[key].tasks.push(task);
        grouped[key].totalBranches++;
        
        // Use the earliest created date for the group
        if (!grouped[key].createdAt || new Date(task.createdAt) < new Date(grouped[key].createdAt)) {
            grouped[key].createdAt = task.createdAt;
        }
        
        if (task.status === 'Completed') {
            grouped[key].completedBranches++;
        }
    });
    
    return Object.values(grouped);
}

function renderTasks() {
    const gridContainer = document.getElementById('tasksContainer');
    const listContainer = document.getElementById('tasksListContainer');
    const emptyState = document.getElementById('emptyState');

    gridContainer.innerHTML = '';
    listContainer.innerHTML = '';

    let tasksToRender = [];

    if (appState.currentUser && appState.currentUser.role === 'admin') {
        tasksToRender = appState.filteredTasks;
        gridContainer.classList.add('hidden');
        listContainer.classList.remove('hidden');
        renderAdminSummaryView(tasksToRender, listContainer); // NEW: Admin summary view
    } else {
        if (appState.activeTab === 'active') {
            tasksToRender = appState.filteredTasks.filter(task => task.status !== 'Completed');
        } else {
            tasksToRender = appState.filteredTasks.filter(task => task.status === 'Completed');
        }

        if (tasksToRender.length === 0) {
            emptyState.classList.remove('hidden');
            return;
        }

        emptyState.classList.add('hidden');

        if (appState.currentViewMode === 'grid') {
            gridContainer.classList.remove('hidden');
            listContainer.classList.add('hidden');
            renderGridView(tasksToRender, gridContainer);
        } else {
            gridContainer.classList.add('hidden');
            listContainer.classList.remove('hidden');
            renderUserListView(tasksToRender, listContainer); // User list view
        }
    }

    if (tasksToRender.length === 0) {
        emptyState.classList.remove('hidden');
    } else {
        emptyState.classList.add('hidden');
    }
}

// NEW: Admin Summary View - Groups tasks by title with Created At column
function renderAdminSummaryView(tasks, container) {
    const groupedTasks = groupTasksByTitle(tasks);
    
    if (groupedTasks.length === 0) {
        container.innerHTML = '<div class="text-center py-8 text-gray-500">No tasks found</div>';
        return;
    }
    
    container.innerHTML = `
        <div class="admin-summary-header">
            <div class="summary-col-title">Task Name</div>
            <div class="summary-col-branches">Branch Count</div>
            <div class="summary-col-created">Created At</div>
            <div class="summary-col-date">Due Date</div>
            <div class="summary-col-completion">Completed %</div>
            <div class="summary-col-actions">Actions</div>
        </div>
        ${groupedTasks.map(group => {
            const completionPercentage = group.totalBranches > 0 
                ? Math.round((group.completedBranches / group.totalBranches) * 100) 
                : 0;
            
            const dueDateFormatted = group.dueDate ? new Date(group.dueDate).toLocaleDateString() : 'No date';
            const createdAtFormatted = group.createdAt ? new Date(group.createdAt).toLocaleDateString() : 'Unknown';
            
            const firstTaskId = group.tasks[0].Id; // Use first task for edit/delete actions
            
            return `
                <div class="admin-summary-item fade-in" onclick="showTaskBranchDetails('${group.title}')" data-task-title="${group.title}">
                    <div class="summary-col-title">
                        <h3 class="text-base font-semibold text-gray-800">${group.title}</h3>
                        <p class="text-xs text-gray-500 mt-1">${group.description}</p>
                    </div>
                    <div class="summary-col-branches">
                        <span class="text-lg font-bold text-blue-600">${group.totalBranches}</span>
                        <span class="text-xs text-gray-500 block">branches</span>
                    </div>
                    <div class="summary-col-created">
                        <span class="text-sm text-gray-600">${createdAtFormatted}</span>
                    </div>
                    <div class="summary-col-date">
                        <span class="text-sm text-gray-600">${dueDateFormatted}</span>
                    </div>
                    <div class="summary-col-completion">
                        <div class="flex items-center space-x-2">
                            <div class="w-16 bg-gray-200 rounded-full h-2">
                                <div class="bg-green-600 h-2 rounded-full" style="width: ${completionPercentage}%"></div>
                            </div>
                            <span class="text-sm font-medium ${completionPercentage === 100 ? 'text-green-600' : 'text-gray-700'}">${completionPercentage}%</span>
                        </div>
                        <span class="text-xs text-gray-500">${group.completedBranches}/${group.totalBranches} completed</span>
                    </div>
                    <div class="summary-col-actions">
                        <div class="flex space-x-2">
                            <button onclick="event.stopPropagation(); editTaskGroup('${firstTaskId}')" class="text-blue-500 hover:text-blue-700 text-sm" title="Edit Task">
                                <i class="fas fa-edit"></i>
                            </button>
                            <button onclick="event.stopPropagation(); deleteTaskGroup('${group.title}')" class="text-red-500 hover:text-red-700 text-sm" title="Delete All Tasks">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }).join('')}
    `;
}

function renderGridView(tasks, container) {
    container.innerHTML = tasks.map(task => {
        const isOverdue = task.status !== 'Completed' && new Date(task.dueDate) < new Date();
        const statusClass = isOverdue ? 'overdue' : task.status.toLowerCase().replace(' ', '');
        const priorityClass = `priority-${(task.priority || '').toLowerCase()}`;

        const actionsHtml = appState.currentUser.role === 'admin'
            ? `
                <div class="flex space-x-2">
                    <button onclick="event.stopPropagation(); editTask('${task.Id}')" class="text-blue-500 hover:text-blue-700 text-sm" title="Edit Task">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button onclick="event.stopPropagation(); deleteTask('${task.Id}')" class="text-red-500 hover:text-red-700 text-sm" title="Delete Task">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
              `
            : `
                ${task.status !== 'Completed' ? `
                    <button onclick="event.stopPropagation(); openCompleteTaskModal('${task.Id}')" class="bg-green-500 hover:bg-green-600 text-white px-3 py-1 rounded-lg text-xs transition duration-300" title="Mark as Completed">
                        <i class="fas fa-check mr-1"></i>Complete
                    </button>
                ` : `
                    <span class="text-green-600 text-xs font-medium">
                        <i class="fas fa-check-circle mr-1"></i>Completed
                    </span>
                `}
              `;

        return `
            <div class="task-card bg-white rounded-xl shadow-sm p-6 ${priorityClass} fade-in" onclick="openTaskDetailModal('${task.Id}')" data-task-id="${task.Id}">
                <div class="flex justify-between items-start mb-4">
                    <h3 class="text-lg font-semibold text-gray-800 line-clamp-2">${task.title}</h3>
                    <span class="status-${statusClass} px-3 py-1 rounded-full text-xs font-medium">
                        ${isOverdue ? 'Overdue' : task.status}
                    </span>
                </div>
                <p class="text-gray-600 text-sm mb-4 line-clamp-3">${task.description}</p>
                <div class="space-y-2 mb-4">
                    <div class="flex items-center text-sm text-gray-600">
                        <i class="fas fa-building w-4 mr-2"></i>
                        <span>${task.branch}</span>
                    </div>
                    <div class="flex items-center text-sm text-gray-600">
                        <i class="fas fa-user w-4 mr-2"></i>
                        <span>${task.assignee}</span>
                    </div>
                    <div class="flex items-center text-sm text-gray-600">
                        <i class="fas fa-calendar w-4 mr-2"></i>
                        <span>${task.dueDate ? new Date(task.dueDate).toLocaleDateString() : 'No date'}</span>
                    </div>
                </div>
                <div class="flex justify-between items-center">
                    <span class="text-xs font-medium px-2 py-1 rounded-full ${getPriorityBadgeClass(task.priority)}">
                        ${task.priority} Priority
                    </span>
                    ${actionsHtml}
                </div>
            </div>
        `;
    }).join('');
}

function renderUserListView(tasks, container) {
    container.innerHTML = `
        <div class="list-header">
            <div class="list-col-title">Task Title</div>
            <div class="list-col-branch">Branch</div>
            <div class="list-col-date">Due Date</div>
            <div class="list-col-status">Status</div>
            <div class="list-col-actions">Actions</div>
        </div>
        ${tasks.map(task => {
            const isOverdue = task.status !== 'Completed' && new Date(task.dueDate) < new Date();
            const statusClass = isOverdue ? 'overdue' : task.status.toLowerCase().replace(' ', '');
            const dueDateFormatted = task.dueDate ? new Date(task.dueDate).toLocaleDateString() : 'No date';

            const actionsHtml = `
                ${task.status !== 'Completed' ? `
                    <button onclick="event.stopPropagation(); openCompleteTaskModal('${task.Id}')" class="bg-green-500 hover:bg-green-600 text-white px-3 py-1 rounded-lg text-xs transition duration-300" title="Mark as Completed">
                        <i class="fas fa-check mr-1"></i>Complete
                    </button>
                ` : `
                    <span class="text-green-600 text-xs font-medium">
                        <i class="fas fa-check-circle mr-1"></i>Completed
                    </span>
                `}
              `;

            return `
                <div class="list-item fade-in" onclick="openTaskDetailModal('${task.Id}')" data-task-id="${task.Id}">
                    <div class="list-col-title">
                        <h3 class="text-base font-semibold text-gray-800 line-clamp-2">${task.title}</h3>
                    </div>
                    <div class="list-col-branch">
                        <span class="text-sm text-gray-600">${task.branch}</span>
                    </div>
                    <div class="list-col-date">
                        <span class="text-sm text-gray-600">${dueDateFormatted}</span>
                    </div>
                    <div class="list-col-status">
                        <span class="status-${statusClass} px-3 py-1 rounded-full text-xs font-medium">
                            ${isOverdue ? 'Overdue' : task.status}
                        </span>
                    </div>
                    <div class="list-col-actions">
                        ${actionsHtml}
                    </div>
                </div>
            `;
        }).join('')}
    `;
}

// NEW: Show branch details for a specific task
function showTaskBranchDetails(taskTitle) {
    const tasksForTitle = appState.filteredTasks.filter(task => task.title === taskTitle);
    
    if (tasksForTitle.length === 0) {
        showNotification('No tasks found for this title', 'error');
        return;
    }
    
    // Show modal with branch details
    const modal = document.getElementById('branchDetailsModal');
    const modalBody = document.getElementById('branchDetailsBody');
    const modalTitle = document.getElementById('branchDetailsTitle');
    
    modalTitle.textContent = `Branches for: ${taskTitle}`;
    
    modalBody.innerHTML = `
        <div class="branch-details-header">
            <div class="branch-col-branch">Branch</div>
            <div class="branch-col-status">Status</div>
            <div class="branch-col-assignee">Assignee</div>
            <div class="branch-col-note">Note</div>
        </div>
        ${tasksForTitle.map(task => {
            const statusClass = task.status.toLowerCase().replace(' ', '');
            return `
                <div class="branch-details-item" onclick="openTaskDetailModal('${task.Id}')">
                    <div class="branch-col-branch">
                        <span class="font-medium">${task.branch}</span>
                    </div>
                    <div class="branch-col-status">
                        <span class="status-${statusClass} px-2 py-1 rounded text-xs">${task.status}</span>
                    </div>
                    <div class="branch-col-assignee">
                        <span class="text-sm text-gray-600">${task.assignee}</span>
                    </div>
                    <div class="branch-col-note">
                        <span class="text-xs text-gray-500">${task.userNote || 'No note'}</span>
                    </div>
                </div>
            `;
        }).join('')}
    `;
    
    modal.classList.add('show');
}

// NEW: Close branch details modal
function closeBranchDetailsModal() {
    document.getElementById('branchDetailsModal').classList.remove('show');
}

// NEW: Edit task group (edit the template task)
function editTaskGroup(taskId) {
    editTask(taskId);
}

// NEW: Delete entire task group
async function deleteTaskGroup(taskTitle) {
    const tasksToDelete = appState.allTasks.filter(task => task.title === taskTitle);
    
    if (tasksToDelete.length === 0) {
        showNotification('No tasks found to delete', 'error');
        return;
    }
    
    if (!confirm(`Are you sure you want to delete "${taskTitle}" for all ${tasksToDelete.length} branches?`)) {
        return;
    }
    
    try {
        // Delete all tasks with this title
        for (const task of tasksToDelete) {
            const url = `${_config.getBase()}${_config.tables.t}/${task.Id}/`;
            await apiClient.makeRequest(url, { method: 'DELETE' });
        }
        
        // Remove from local state
        appState.allTasks = appState.allTasks.filter(task => task.title !== taskTitle);
        appState.filteredTasks = appState.filteredTasks.filter(task => task.title !== taskTitle);
        
        showNotification(`Task "${taskTitle}" deleted for all branches successfully!`, 'success');
        updateStats();
        renderTasks();
        populateFilters();
        
    } catch (error) {
        showNotification(`Failed to delete tasks: ${error.message}`, 'error');
    }
}

function getPriorityBadgeClass(priority) {
    switch (priority.toLowerCase()) {
        case 'high': return 'bg-red-100 text-red-800';
        case 'medium': return 'bg-yellow-100 text-yellow-800';
        case 'low': return 'bg-green-100 text-green-800';
        default: return 'bg-gray-100 text-gray-800';
    }
}

function populateFilters() {
    if (appState.currentUser && appState.currentUser.role !== 'admin') return;

    const branches = [...new Set(appState.allTasks.map(task => task.branch).filter(b => b))];
    const assignees = [...new Set(appState.allTasks.map(task => task.assignee).filter(a => a))];

    const branchFilter = document.getElementById('branchFilter');
    const userFilter = document.getElementById('userFilter');

    branchFilter.innerHTML = '<option value="">All Branches</option>' +
        branches.map(branch => `<option value="${branch}">${branch}</option>`).join('');

    userFilter.innerHTML = '<option value="">All Users</option>' +
        assignees.map(assignee => `<option value="${assignee}">${assignee}</option>`).join('');
}

function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    const icon = document.getElementById('notificationIcon');
    const messageEl = document.getElementById('notificationMessage');

    messageEl.textContent = validateInput(message, 'text', 200);

    const notificationDiv = notification.querySelector('div');
    notificationDiv.className = 'bg-white rounded-lg shadow-lg p-4';

    switch (type) {
        case 'success':
            notificationDiv.classList.add('border-l-4', 'border-green-500');
            icon.className = 'fas fa-check-circle text-green-500';
            break;
        case 'error':
            notificationDiv.classList.add('border-l-4', 'border-red-500');
            icon.className = 'fas fa-exclamation-circle text-red-500';
            break;
        case 'warning':
            notificationDiv.classList.add('border-l-4', 'border-yellow-500');
            icon.className = 'fas fa-exclamation-triangle text-yellow-500';
            break;
        default:
            notificationDiv.classList.add('border-l-4', 'border-blue-500');
            icon.className = 'fas fa-info-circle text-blue-500';
    }

    notification.classList.add('show');
    setTimeout(() => hideNotification(), 5000);
}

function hideNotification() {
    document.getElementById('notification').classList.remove('show');
}

function refreshTasks() {
    loadTasks();
}

function clearAllFilters() {
    ['branchFilter', 'userFilter', 'statusFilter', 'priorityFilter'].forEach(id => {
        document.getElementById(id).value = '';
    });
    filterTasks();
}

function updateFilterSummary() {
    if (appState.currentUser && appState.currentUser.role !== 'admin') {
        document.getElementById('filterSummary').classList.add('hidden');
        return;
    }

    const filters = [];
    const branch = document.getElementById('branchFilter').value;
    const user = document.getElementById('userFilter').value;
    const status = document.getElementById('statusFilter').value;
    const priority = document.getElementById('priorityFilter').value;

    if (branch) filters.push(`Branch: ${branch}`);
    if (user) filters.push(`User: ${user}`);
    if (status) filters.push(`Status: ${status}`);
    if (priority) filters.push(`Priority: ${priority}`);

    const filterSummary = document.getElementById('filterSummary');
    const filterSummaryText = document.getElementById('filterSummaryText');

    if (filters.length > 0) {
        filterSummaryText.textContent = filters.join(', ');
        filterSummary.classList.remove('hidden');
    } else {
        filterSummary.classList.add('hidden');
    }
}

function toggleDebug() {
    appState.debugMode = !appState.debugMode; // Toggle debug mode
    const debugInfo = document.getElementById('debugInfo');

    if (appState.debugMode) {
        debugInfo.classList.remove('hidden');
        document.getElementById('loadedUsers').textContent = JSON.stringify(
            appState.users.map(user => ({
                username: user.username,
                role: user.role,
                fullName: user.fullName,
                hasPassword: !!user.password
            })), null, 2
        );
        // Populate API response and available fields if available
        document.getElementById('apiResponse').textContent = JSON.stringify(appState.allTasks.slice(0, 5), null, 2); // Show first 5 tasks
        document.getElementById('availableFields').textContent = JSON.stringify(appState.availableFields, null, 2);
    } else {
        debugInfo.classList.add('hidden');
    }
}

function openTaskModal(taskId = null) {
    const modal = document.getElementById('taskModal');
    const title = document.getElementById('modalTitle');
    const taskIdInput = document.getElementById('taskId');
    const userNoteField = document.getElementById('userNoteField');
    const assignToAllNonAdminUsersContainer = document.getElementById('assignToAllNonAdminUsersContainer');

    document.getElementById('taskForm').reset();
    taskIdInput.value = '';

    if (taskId) {
        const task = findTaskById(taskId);
        if (task) {
            title.textContent = 'Edit Task';
            taskIdInput.value = task.Id;
            document.getElementById('taskTitle').value = task.title;
            document.getElementById('taskDescription').value = task.description;
            document.getElementById('taskBranch').value = task.branch;
            document.getElementById('taskPriority').value = task.priority;
            document.getElementById('taskDueDate').value = task.dueDate;
            document.getElementById('taskStatus').value = task.status;
            document.getElementById('taskUserNote').value = task.userNote || '';
        }
    } else {
        title.textContent = 'Add New Task';
    }

    const isAdmin = appState.currentUser && appState.currentUser.role === 'admin';
    const fields = ['taskTitle', 'taskDescription', 'taskBranch', 'taskPriority', 'taskDueDate'];

    fields.forEach(fieldId => {
        document.getElementById(fieldId).disabled = !isAdmin;
    });

    if (isAdmin && !taskId) {
        userNoteField.classList.add('hidden');
        assignToAllNonAdminUsersContainer.classList.remove('hidden'); // Show for admin creating new task
    } else {
        userNoteField.classList.add('hidden'); // User note is for users, not for admin creating tasks
        assignToAllNonAdminUsersContainer.classList.add('hidden'); // Hide for non-admin or editing existing task
    }
    
    // Ensure taskStatus and taskUserNote are enabled for all users when editing
    document.getElementById('taskStatus').disabled = false;
    document.getElementById('taskUserNote').disabled = false;

    modal.classList.add('show');
}

function closeTaskModal() {
    document.getElementById('taskModal').classList.remove('show');
}

function openTaskDetailModal(taskId) {
    const task = findTaskById(taskId);
    if (!task) {
        showNotification('Task not found', 'error');
        return;
    }

    appState.currentDetailTaskId = taskId;

    document.getElementById('detailModalTitle').textContent = task.title;
    document.getElementById('detailTaskTitle').textContent = task.title;
    document.getElementById('detailTaskDescription').textContent = task.description || 'No description provided.';
    document.getElementById('detailTaskBranch').textContent = task.branch || 'N/A';
    document.getElementById('detailTaskPriority').textContent = task.priority || 'N/A';
    document.getElementById('detailTaskAssignee').textContent = task.assignee || 'Unassigned';
    document.getElementById('detailTaskDueDate').textContent = task.dueDate ? new Date(task.dueDate).toLocaleDateString() : 'No date';
    document.getElementById('detailTaskStatus').textContent = task.status || 'N/A';

    const detailUserNoteContainer = document.getElementById('detailUserNoteContainer');
    const detailTaskUserNote = document.getElementById('detailTaskUserNote');

    if (task.userNote) {
        detailTaskUserNote.textContent = task.userNote;
        detailUserNoteContainer.classList.remove('hidden');
    } else {
        detailUserNoteContainer.classList.add('hidden');
    }

    const detailEditBtn = document.getElementById('detailEditBtn');
    const detailEditNoteBtn = document.getElementById('detailEditNoteBtn');

    if (appState.currentUser && appState.currentUser.role === 'admin') {
        detailEditBtn.classList.remove('hidden');
        detailEditNoteBtn.classList.add('hidden');
    } else {
        detailEditBtn.classList.add('hidden');
        detailEditNoteBtn.classList.remove('hidden');
    }

    document.getElementById('taskDetailModal').classList.add('show');
}

function closeTaskDetailModal() {
    document.getElementById('taskDetailModal').classList.remove('show');
    appState.currentDetailTaskId = null;
}

function editTask(taskId) {
    closeTaskDetailModal();
    openTaskModal(taskId);
}

function editTaskFromDetail() {
    if (appState.currentDetailTaskId) {
        editTask(appState.currentDetailTaskId);
    }
}

function openCompleteTaskModal(taskId) {
    appState.taskIdToComplete = taskId;
    const task = findTaskById(taskId);
    if (!task) {
        showNotification('Task not found for completion.', 'error');
        return;
    }

    document.getElementById('completeTaskTitle').textContent = task.title;
    document.getElementById('completeTaskNote').value = task.userNote || '';

    const currentNoteContainer = document.getElementById('currentNoteContainer');
    const currentNoteText = document.getElementById('currentNoteText');

    if (task.userNote) {
        currentNoteText.textContent = task.userNote;
        currentNoteContainer.classList.remove('hidden');
    } else {
        currentNoteContainer.classList.add('hidden');
    }

    document.getElementById('completeTaskModal').classList.add('show');
}

function closeCompleteTaskModal() {
    document.getElementById('completeTaskModal').classList.remove('show');
    appState.taskIdToComplete = null;
}

async function confirmCompleteTask() {
    if (!appState.taskIdToComplete) {
        showNotification('No task selected for completion.', 'error');
        return;
    }

    const note = validateInput(document.getElementById('completeTaskNote').value, 'text', 500);
    const confirmBtn = document.getElementById('confirmCompleteBtn');
    const confirmText = document.getElementById('confirmCompleteText');
    const confirmSpinner = document.getElementById('confirmCompleteSpinner');

    confirmBtn.disabled = true;
    confirmText.textContent = 'Completing...';
    confirmSpinner.classList.remove('hidden');

    try {
        const url = `${_config.getBase()}${_config.tables.t}/${appState.taskIdToComplete}/?user_field_names=true`;
        const response = await apiClient.makeRequest(url, {
            method: 'PATCH',
            body: JSON.stringify({
                'Status': 'Completed',
                'User Note': note
            })
        });

        const updatedRecord = await response.json();
        const task = findTaskById(appState.taskIdToComplete);
        if (task) {
            task.status = 'Completed';
            task.userNote = note;
        }

        showNotification('Task marked as completed successfully!', 'success');

        closeCompleteTaskModal();
        filterTasks();
        updateStats();

    } catch (error) {
        showNotification(`Failed to update task status: ${error.message}`, 'error');
    } finally {
        confirmBtn.disabled = false;
        confirmText.textContent = 'Complete Task';
        confirmSpinner.classList.add('hidden');
    }
}

async function deleteTask(taskId) {
    if (!confirm('Are you sure you want to delete this task?')) return;

    try {
        const url = `${_config.getBase()}${_config.tables.t}/${taskId}/`;
        await apiClient.makeRequest(url, { method: 'DELETE' });
        showNotification('Task deleted successfully!', 'success');

        appState.allTasks = appState.allTasks.filter(task => String(task.Id) !== String(taskId));
        appState.filteredTasks = appState.filteredTasks.filter(task => String(task.Id) !== String(taskId));
        updateStats();
        renderTasks();
        populateFilters();

    } catch (error) {
        showNotification(`Failed to delete task: ${error.message}`, 'error');
    }
}

// IMPROVED: Create New Tasks with better batch handling and progress tracking
async function createNewTasks() {
    const assignToAllNonAdmin = document.getElementById('assignToAllNonAdminUsersCheckbox').checked;
    let tasksToCreate = [];

    if (assignToAllNonAdmin) {
        const nonAdminUsers = appState.users.filter(user => user.role !== 'admin');
        if (nonAdminUsers.length === 0) {
            throw new Error('No non-admin users found to assign tasks to.');
        }

        // When assigning to all non-admin users, the assignee should be the admin
        const adminAssignee = appState.currentUser.fullName || appState.currentUser.username;

        nonAdminUsers.forEach(user => {
            // The branch should be the user's username if they are a branch user
            const branch = user.username;
            tasksToCreate.push(getValidatedTaskDataForUser(adminAssignee, branch));
        });
    } else {
        const assignee = appState.currentUser.fullName || appState.currentUser.username;
        const branch = validateInput(document.getElementById('taskBranch').value); // Get branch from input
        tasksToCreate.push(getValidatedTaskDataForUser(assignee, branch));
    }

    showNotification(`Starting to create ${tasksToCreate.length} tasks...`, 'info');

    // Use smaller batch size and individual creation for better reliability
    const batchSize = 3; // Reduced from 10 to 3
    let createdCount = 0;
    let failedCount = 0;

    try {
        for (let i = 0; i < tasksToCreate.length; i += batchSize) {
            const batch = tasksToCreate.slice(i, i + batchSize);
            
            // Update progress
            showNotification(`Creating tasks ${i + 1}-${Math.min(i + batch.length, tasksToCreate.length)} of ${tasksToCreate.length}...`, 'info');

            try {
                // Try batch creation first
                const url = `${_config.getBase()}${_config.tables.t}/batch/?user_field_names=true`;
                
                const response = await apiClient.makeRequest(url, {
                    method: 'POST',
                    body: JSON.stringify({ items: batch })
                });

                const newRecordsResponse = await response.json();
                let createdRecords = Array.isArray(newRecordsResponse) ? newRecordsResponse :
                                   newRecordsResponse.results || newRecordsResponse.items || [];

                // If batch creation doesn't return expected results, try individual creation
                if (!createdRecords || createdRecords.length === 0) {
                    console.log('Batch creation failed, trying individual creation...');
                    
                    // Create tasks individually
                    for (const taskData of batch) {
                        try {
                            const singleUrl = `${_config.getBase()}${_config.tables.t}/?user_field_names=true`;
                            const singleResponse = await apiClient.makeRequest(singleUrl, {
                                method: 'POST',
                                body: JSON.stringify(taskData)
                            });

                            const singleRecord = await singleResponse.json();
                            if (singleRecord && (singleRecord.id || singleRecord.Id)) {
                                const newTask = {
                                    Id: String(singleRecord.id || singleRecord.Id),
                                    title: validateInput(singleRecord.Title || ''),
                                    description: validateInput(singleRecord.Description || ''),
                                    branch: validateInput(singleRecord.Branch || ''),
                                    priority: validateInput(singleRecord.Priority || ''),
                                    assignee: validateInput(singleRecord.Assignee || ''),
                                    dueDate: validateInput(singleRecord['Due Date'] || '', 'date'),
                                    status: validateInput(singleRecord.Status || 'Pending'),
                                    userNote: validateInput(singleRecord['User Note'] || ''),
                                    createdAt: singleRecord.created_at || singleRecord.Created_At || new Date().toISOString()
                                };
                                appState.allTasks.push(newTask);
                                createdCount++;
                            }

                            // Add delay between individual requests
                            await new Promise(resolve => setTimeout(resolve, 500));

                        } catch (singleError) {
                            console.error('Failed to create individual task:', singleError);
                            failedCount++;
                        }
                    }
                } else {
                    // Process batch creation results
                    createdRecords.forEach(record => {
                        if (record && (record.id || record.id)) { // Check for both 'id' and 'Id'
                            const newTask = {
                                Id: String(record.id || record.Id),
                                title: validateInput(record.Title || ''),
                                description: validateInput(record.Description || ''),
                                branch: validateInput(record.Branch || ''),
                                priority: validateInput(record.Priority || ''),
                                assignee: validateInput(record.Assignee || ''),
                                dueDate: validateInput(record['Due Date'] || '', 'date'),
                                status: validateInput(record.Status || 'Pending'),
                                userNote: validateInput(record['User Note'] || ''),
                                createdAt: record.created_at || record.Created_At || new Date().toISOString()
                            };
                            appState.allTasks.push(newTask);
                            createdCount++;
                        }
                    });
                }

            } catch (batchError) {
                console.error('Batch creation failed, trying individual creation:', batchError);
                
                // Create tasks individually as fallback
                for (const taskData of batch) {
                    try {
                        const singleUrl = `${_config.getBase()}${_config.tables.t}/?user_field_names=true`;
                        const singleResponse = await apiClient.makeRequest(singleUrl, {
                            method: 'POST',
                            body: JSON.stringify(taskData)
                        });

                        const singleRecord = await singleResponse.json();
                        if (singleRecord && (singleRecord.id || singleRecord.Id)) {
                            const newTask = {
                                Id: String(singleRecord.id || singleRecord.Id),
                                title: validateInput(singleRecord.Title || ''),
                                description: validateInput(singleRecord.Description || ''),
                                branch: validateInput(singleRecord.Branch || ''),
                                priority: validateInput(singleRecord.Priority || ''),
                                assignee: validateInput(singleRecord.Assignee || ''),
                                dueDate: validateInput(singleRecord['Due Date'] || '', 'date'),
                                status: validateInput(singleRecord.Status || 'Pending'),
                                userNote: validateInput(singleRecord['User Note'] || ''),
                                createdAt: singleRecord.created_at || singleRecord.Created_At || new Date().toISOString()
                            };
                            appState.allTasks.push(newTask);
                            createdCount++;
                        }

                        // Add delay between individual requests
                        await new Promise(resolve => setTimeout(resolve, 500));

                    } catch (singleError) {
                        console.error('Failed to create individual task:', singleError);
                        failedCount++;
                    }
                }
            }

            // Add delay between batches to avoid rate limiting
            if (i + batchSize < tasksToCreate.length) {
                await new Promise(resolve => setTimeout(resolve, 1000)); // 1 second delay
            }
        }

        // Show final result
        if (createdCount > 0) {
            showNotification(`Successfully created ${createdCount} tasks!${failedCount > 0 ? ` ${failedCount} failed.` : ''}`, 'success');
        } else {
            throw new Error('Failed to create any tasks');
        }

    } catch (error) {
        console.error('Task creation error:', error);
        if (createdCount > 0) {
            showNotification(`Created ${createdCount} tasks, but encountered errors. ${failedCount} tasks failed.`, 'warning');
        } else {
            throw new Error(`Failed to create tasks: ${error.message}`);
        }
    }
}

function getValidatedTaskDataForUser(assignee, branch) {
    return {
        'Title': validateInput(document.getElementById('taskTitle').value, 'text', 200),
        'Description': validateInput(document.getElementById('taskDescription').value, 'text', 1000),
        'Branch': validateInput(branch),
        'Priority': validateInput(document.getElementById('taskPriority').value),
        'Assignee': validateInput(assignee),
        'Due Date': validateInput(document.getElementById('taskDueDate').value, 'date'),
        'Status': validateInput(document.getElementById('taskStatus').value),
        'User Note': validateInput(document.getElementById('taskUserNote').value, 'text', 500)
    };
}

function setActiveTab(tabName) {
    appState.activeTab = tabName;

    document.getElementById('activeTasksTab').classList.remove('active');
    document.getElementById('completedTasksTab').classList.remove('active');

    if (tabName === 'active') {
        document.getElementById('activeTasksTab').classList.add('active');
    } else {
        document.getElementById('completedTasksTab').classList.add('active');
    }

    renderTasks();
}

// New function to set view mode
function setViewMode(mode) {
    appState.currentViewMode = mode;
    const gridBtn = document.getElementById('gridViewBtn');
    const listBtn = document.getElementById('listViewBtn');

    if (gridBtn && listBtn) {
        if (mode === 'grid') {
            gridBtn.classList.add('active');
            listBtn.classList.remove('active');
        } else {
            listBtn.classList.add('active');
            gridBtn.classList.remove('active');
        }
    }
    renderTasks();
}


// Enhanced event handling with security focus
document.addEventListener('click', function(e) {
    const modals = ['taskModal', 'taskDetailModal', 'completeTaskModal', 'branchDetailsModal'];
    modals.forEach(modalId => {
        const modal = document.getElementById(modalId);
        if (modal && e.target === modal) {
            modal.classList.remove('show');
        }
    });
});

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        ['taskModal', 'taskDetailModal', 'completeTaskModal', 'branchDetailsModal'].forEach(modalId => {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.classList.remove('show');
            }
        });
        hideNotification();
    }

    if ((e.ctrlKey || e.metaKey) && e.key === 'n' && appState.currentUser && appState.currentUser.role === 'admin') {
        e.preventDefault();
        openTaskModal();
    }

    if (e.key === 'F5' || ((e.ctrlKey || e.metaKey) && e.key === 'r')) {
        if (appState.currentUser) {
            e.preventDefault();
            refreshTasks();
        }
    }
});

// Removed aggressive security measures and console clearing for debugging purposes.
// For production, a secure backend is highly recommended.
