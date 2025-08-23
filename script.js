
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

// Enhanced configuration with basic obfuscation (still not secure)
const _config = {
    // API key split into parts for basic obfuscation (easily reversible)
    k1: '19pWWNEBYlep9VU6gT',
    k2: 'cYDknYzzrefKoN',
    dbId: '276777',
    baseUrl: 'https://api.baserow.io/api/database/rows/table/',
    tables: { users: '647091', tasks: '647088' }
};

// Reconstruct API key (this is NOT secure - just obfuscation)
const getApiKey = () => _config.k1 + _config.k2;

// Enhanced password hashing with salt (still client-side, so not truly secure)
const createSecureHash = (password, salt = 'taskapp2024') => {
    // Multiple rounds of hashing with salt for better security
    let hash = password + salt;
    for (let i = 0; i < 1000; i++) {
        hash = CryptoJS.SHA256(hash).toString();
    }
    return hash;
};

// Admin credentials - using enhanced hashing
const ADMIN_CONFIG = {
    u: 'admin',
    // Enhanced hash of 'admin123' with salt
    h: createSecureHash('admin123')
};

// Global state management
let appState = {
    currentUser: null,
    allTasks: [],
    users: [],
    filteredTasks: [],
    debugMode: false,
    availableFields: [],
    userFields: [],
    currentDetailTaskId: null,
    activeTab: 'active',
    taskIdToComplete: null
};

// Security-enhanced user defaults with better hashing
const getDefaultUsers = () => [
    { username: 'user1', password: createSecureHash('password1'), role: 'user', fullName: 'John User' },
    { username: 'user2', password: createSecureHash('password2'), role: 'user', fullName: 'Jane User' },
    { username: 'user3', password: createSecureHash('password3'), role: 'user', fullName: 'Bob User' },
    { username: 'manager1', password: createSecureHash('manager123'), role: 'manager', fullName: 'Alice Manager' },
    { username: 'manager2', password: createSecureHash('manager456'), role: 'manager', fullName: 'Mike Manager' },
    { username: 'supervisor1', password: createSecureHash('super123'), role: 'supervisor', fullName: 'Sarah Supervisor' },
    { username: 'employee1', password: createSecureHash('emp123'), role: 'employee', fullName: 'Tom Employee' },
    { username: 'employee2', password: createSecureHash('emp456'), role: 'employee', fullName: 'Lisa Employee' },
    { username: 'C001', password: createSecureHash('branchpass'), role: 'branch_user', fullName: 'Branch C001 User' },
    { username: 'C003', password: createSecureHash('1234'), role: 'user', fullName: 'Branch C003 User' },
    { username: 'C004', password: createSecureHash('1234'), role: 'user', fullName: 'Branch C004 User' }
];

// Enhanced input validation and sanitization
const validateInput = (input, type = 'text', maxLength = 255) => {
    if (!input || typeof input !== 'string') return '';
    
    // Basic XSS prevention
    const sanitized = input
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
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

// Secure API request wrapper with rate limiting
class SecureApiClient {
    constructor() {
        this.requestCount = 0;
        this.lastRequestTime = 0;
        this.rateLimitDelay = 100; // Minimum delay between requests
    }
    
    async makeRequest(endpoint, options = {}) {
        // Simple rate limiting
        const now = Date.now();
        const timeSinceLastRequest = now - this.lastRequestTime;
        if (timeSinceLastRequest < this.rateLimitDelay) {
            await new Promise(resolve => setTimeout(resolve, this.rateLimitDelay - timeSinceLastRequest));
        }
        
        this.lastRequestTime = Date.now();
        this.requestCount++;
        
        // Add authentication header
        const headers = {
            'Authorization': `Token ${getApiKey()}`,
            'Content-Type': 'application/json',
            ...options.headers
        };
        
        try {
            const response = await fetch(endpoint, {
                ...options,
                headers
            });
            
            if (!response.ok) {
                throw new Error(`API Error: ${response.status} - ${response.statusText}`);
            }
            
            return response;
        } catch (error) {
            console.error('API Request failed:', error.message);
            throw error;
        }
    }
}

const apiClient = new SecureApiClient();

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

async function initializeApp() {
    try {
        showNotification('Initializing application...', 'info');
        await loadUsers();
        setupEventListeners();
        checkSavedLogin();
        showNotification('Application initialized successfully', 'success');
    } catch (error) {
        console.error('App initialization failed:', error);
        showNotification('Failed to initialize application', 'error');
    }
}

// Enhanced user loading with better error handling
async function loadUsers() {
    try {
        const url = `${_config.baseUrl}${_config.tables.users}/?user_field_names=true`;
        console.log('Loading users from Baserow...');
        
        const response = await apiClient.makeRequest(url);
        const data = await response.json();
        
        if (data.results && data.results.length > 0) {
            appState.userFields = Object.keys(data.results[0]);
            
            // Enhanced user processing with validation
            appState.users = data.results.map(record => {
                const username = validateInput(record.Username || record.username || '', 'username');
                const password = validateInput(record.Password || record.password || '');
                const role = validateInput(record.Role || record.role || 'user').toLowerCase();
                const fullName = validateInput(record.FullName || record['Full Name'] || username);
                
                if (!username || !password) {
                    console.warn('Skipping invalid user record:', { username, hasPassword: !!password });
                    return null;
                }
                
                return {
                    Id: record.id || record.Id,
                    username,
                    password: createSecureHash(password), // Enhanced hashing
                    role,
                    fullName
                };
            }).filter(user => user !== null);
            
            console.log(`Successfully loaded ${appState.users.length} users from Baserow`);
        } else {
            throw new Error('No users found in Baserow response');
        }
    } catch (error) {
        console.error('Failed to load users from Baserow:', error);
        console.log('Using fallback default users');
        appState.users = getDefaultUsers();
    }
}

// Enhanced authentication with better security
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
        sessionStorage.setItem('currentUser', JSON.stringify(appState.currentUser));
        showDashboard();
        showNotification('Welcome Administrator!', 'success');
        return;
    }
    
    // Check regular user credentials
    const hashedPassword = createSecureHash(password);
    const user = appState.users.find(u => u.username === username && u.password === hashedPassword);
    
    if (user) {
        // Don't store sensitive information in session
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
}

function showLoginError(message) {
    const errorElement = document.getElementById('loginError');
    errorElement.textContent = message;
    errorElement.classList.remove('hidden');
    setTimeout(() => errorElement.classList.add('hidden'), 3000);
}

// Enhanced task loading with better validation
async function loadTasks() {
    document.getElementById('loadingSpinner').classList.remove('hidden');
    document.getElementById('tasksContainer').innerHTML = '';
    
    try {
        const url = `${_config.baseUrl}${_config.tables.tasks}/?user_field_names=true`;
        console.log('Loading tasks from Baserow...');
        
        const response = await apiClient.makeRequest(url);
        const data = await response.json();
        
        if (data.results && data.results.length > 0) {
            appState.availableFields = Object.keys(data.results[0]);
            
            // Enhanced task processing with validation
            appState.allTasks = data.results.map(record => ({
                Id: String(record.id || record.Id),
                title: validateInput(record.Title || record.title || '', 'text', 200),
                description: validateInput(record.Description || record.description || '', 'text', 1000),
                branch: validateInput(record.Branch || record.branch || ''),
                priority: validateInput(record.Priority || record.priority || ''),
                assignee: validateInput(record.Assignee || record.assignee || ''),
                dueDate: validateInput(record['Due Date'] || record.DueDate || '', 'date'),
                status: validateInput(record.Status || record.status || 'Pending'),
                userNote: validateInput(record['User Note'] || record.UserNote || '', 'text', 500)
            }));
            
            console.log(`Successfully loaded ${appState.allTasks.length} tasks`);
            showNotification('Tasks loaded successfully!', 'success');
        } else {
            throw new Error('No tasks found');
        }
    } catch (error) {
        console.error('Failed to load tasks:', error);
        showNotification('Failed to load tasks. Using demo data.', 'warning');
        appState.allTasks = generateDemoTasks();
    }
    
    document.getElementById('loadingSpinner').classList.add('hidden');
    filterTasks();
    updateStats();
    renderTasks();
    populateFilters();
}

// Enhanced task filtering with better logic
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
        // Admin filtering logic
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

// Enhanced task saving with better validation
async function saveTask() {
    const saveBtn = document.getElementById('saveTaskBtn');
    const saveText = document.getElementById('saveTaskText');
    const saveSpinner = document.getElementById('saveTaskSpinner');
    
    saveBtn.disabled = true;
    saveText.textContent = 'Saving...';
    saveSpinner.classList.remove('hidden');
    
    try {
        const taskId = document.getElementById('taskId').value;
        const isEdit = taskId && !taskId.startsWith('demo');
        
        // Validate required fields
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
        console.error('Error saving task:', error);
        showNotification(`Failed to save task: ${error.message}`, 'error');
    } finally {
        saveBtn.disabled = false;
        saveText.textContent = 'Save Task';
        saveSpinner.classList.add('hidden');
    }
}

// Enhanced task update function
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
    
    const url = `${_config.baseUrl}${_config.tables.tasks}/${taskId}/?user_field_names=true`;
    const response = await apiClient.makeRequest(url, {
        method: 'PATCH',
        body: JSON.stringify(taskData)
    });
    
    const updatedRecord = await response.json();
    
    // Update local task
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
            userNote: validateInput(updatedRecord['User Note'] || '', 'text', 500)
        };
    }
    
    showNotification('Task updated successfully!', 'success');
}

// Get validated task data from form
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

// Demo tasks for fallback
function generateDemoTasks() {
    return [
        {
            Id: 'demo1',
            title: 'Inventory Check - Electronics',
            description: 'Conduct weekly inventory check for electronics department',
            branch: 'Downtown',
            priority: 'High',
            assignee: 'John User',
            dueDate: '2024-01-20',
            status: 'Pending',
            userNote: 'Checked inventory on Monday, found some discrepancies.'
        },
        {
            Id: 'demo2',
            title: 'Staff Training - Customer Service',
            description: 'Organize customer service training for new employees',
            branch: 'Mall',
            priority: 'Medium',
            assignee: 'Alice Manager',
            dueDate: '2024-01-22',
            status: 'In Progress',
            userNote: ''
        },
        {
            Id: 'demo3',
            title: 'Daily Sales Report',
            description: 'Compile and submit daily sales report',
            branch: 'C003',
            priority: 'High',
            assignee: 'Branch C003 User',
            dueDate: '2024-01-15',
            status: 'Pending',
            userNote: 'Need to double check figures for last week.'
        },
        {
            Id: 'demo4',
            title: 'Clean Store Front',
            description: 'Ensure the store front is clean and presentable',
            branch: 'C004',
            priority: 'Low',
            assignee: 'Branch C004 User',
            dueDate: '2024-01-16',
            status: 'Completed',
            userNote: 'Store front cleaned and looking good.'
        }
    ];
}

// Utility functions
function normalizeTaskId(id) {
    return String(id);
}

function findTaskById(taskId) {
    const normalizedId = normalizeTaskId(taskId);
    return appState.allTasks.find(t => normalizeTaskId(t.Id) === normalizedId);
}

function setupEventListeners() {
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    
    // Add security-focused event listeners
    document.addEventListener('contextmenu', function(e) {
        if (!appState.debugMode) {
            e.preventDefault(); // Disable right-click in non-debug mode
        }
    });
    
    // Detect developer tools (basic deterrent)
    let devtools = {
        open: false,
        orientation: null
    };
    
    setInterval(() => {
        if ((window.outerHeight - window.innerHeight > 160) || (window.outerWidth - window.innerWidth > 160)) {
            if (!devtools.open) {
                devtools.open = true;
                if (!appState.debugMode) {
                    console.clear();
                    console.warn('⚠️ Developer tools detected. This application contains sensitive information.');
                }
            }
        } else {
            devtools.open = false;
        }
    }, 500);
}

function checkSavedLogin() {
    const savedUser = sessionStorage.getItem('currentUser');
    if (savedUser) {
        try {
            const sessionUser = JSON.parse(savedUser);
            // Find full user data
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

    if (appState.currentUser.role === 'admin') {
        adminControls.classList.remove('hidden');
        filterControls.classList.remove('hidden');
        userTabs.classList.add('hidden');
        
        // Add admin filter listeners
        ['branchFilter', 'userFilter', 'statusFilter', 'priorityFilter'].forEach(id => {
            document.getElementById(id).addEventListener('change', filterTasks);
        });
    } else {
        adminControls.classList.add('hidden');
        filterControls.classList.add('hidden');
        userTabs.classList.remove('hidden');
    }
    
    loadTasks();
}

function logout() {
    // Clear all sensitive data
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

function renderTasks() {
    const container = document.getElementById('tasksContainer');
    const emptyState = document.getElementById('emptyState');
    
    let tasksToRender = [];
    
    if (appState.currentUser && appState.currentUser.role === 'admin') {
        tasksToRender = appState.filteredTasks;
    } else {
        if (appState.activeTab === 'active') {
            tasksToRender = appState.filteredTasks.filter(task => task.status !== 'Completed');
        } else {
            tasksToRender = appState.filteredTasks.filter(task => task.status === 'Completed');
        }
    }
    
    if (tasksToRender.length === 0) {
        container.innerHTML = '';
        emptyState.classList.remove('hidden');
        return;
    }
    
    emptyState.classList.add('hidden');
    
    container.innerHTML = tasksToRender.map(task => {
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

// Enhanced notification system
function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    const icon = document.getElementById('notificationIcon');
    const messageEl = document.getElementById('notificationMessage');
    
    messageEl.textContent = validateInput(message, 'text', 200); // Sanitize message
    
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
    appState.debugMode = !appState.debugMode;
    const debugInfo = document.getElementById('debugInfo');
    
    if (appState.debugMode) {
        debugInfo.classList.remove('hidden');
        // Show sanitized debug info (no sensitive data)
        document.getElementById('loadedUsers').textContent = JSON.stringify(
            appState.users.map(user => ({
                username: user.username,
                role: user.role,
                fullName: user.fullName,
                hasPassword: !!user.password
            })), null, 2
        );
    } else {
        debugInfo.classList.add('hidden');
    }
}

// Modal and task management functions
function openTaskModal(taskId = null) {
    const modal = document.getElementById('taskModal');
    const title = document.getElementById('modalTitle');
    const taskIdInput = document.getElementById('taskId');
    const userNoteField = document.getElementById('userNoteField');
    
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
    
    // Configure field accessibility based on user role
    const isAdmin = appState.currentUser && appState.currentUser.role === 'admin';
    const fields = ['taskTitle', 'taskDescription', 'taskBranch', 'taskPriority', 'taskDueDate'];
    
    fields.forEach(fieldId => {
        document.getElementById(fieldId).disabled = !isAdmin;
    });
    
    if (isAdmin && !taskId) {
        userNoteField.classList.add('hidden');
    } else {
        userNoteField.classList.remove('hidden');
    }
    
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
        if (appState.taskIdToComplete.startsWith('demo')) {
            const task = findTaskById(appState.taskIdToComplete);
            if (task) {
                task.status = 'Completed';
                task.userNote = note;
            }
            showNotification('Demo task completed!', 'success');
        } else {
            const url = `${_config.baseUrl}${_config.tables.tasks}/${appState.taskIdToComplete}/?user_field_names=true`;
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
        }
        
        closeCompleteTaskModal();
        filterTasks();
        updateStats();
        
    } catch (error) {
        console.error('Error updating task status:', error);
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
        if (!taskId.startsWith('demo')) {
            const url = `${_config.baseUrl}${_config.tables.tasks}/${taskId}/`;
            await apiClient.makeRequest(url, { method: 'DELETE' });
            showNotification('Task deleted successfully!', 'success');
        } else {
            showNotification('Demo task removed locally', 'info');
        }
        
        appState.allTasks = appState.allTasks.filter(task => String(task.Id) !== String(taskId));
        appState.filteredTasks = appState.filteredTasks.filter(task => String(task.Id) !== String(taskId));
        updateStats();
        renderTasks();
        populateFilters();
        
    } catch (error) {
        console.error('Error deleting task:', error);
        showNotification(`Failed to delete task: ${error.message}`, 'error');
    }
}

async function createNewTasks() {
    const assignToAllNonAdmin = document.getElementById('assignToAllNonAdminUsersCheckbox').checked;
    let tasksToCreate = [];
    
    if (assignToAllNonAdmin) {
        const nonAdminUsers = appState.users.filter(user => user.role !== 'admin');
        if (nonAdminUsers.length === 0) {
            throw new Error('No non-admin users found to assign tasks to.');
        }
        
        nonAdminUsers.forEach(user => {
            const assignee = user.fullName || user.username;
            const branch = user.username;
            tasksToCreate.push(getValidatedTaskDataForUser(assignee, branch));
        });
    } else {
        const assignee = appState.currentUser.fullName || appState.currentUser.username;
        const branch = document.getElementById('taskBranch').value;
        tasksToCreate.push(getValidatedTaskDataForUser(assignee, branch));
    }
    
    const batchSize = 10;
    for (let i = 0; i < tasksToCreate.length; i += batchSize) {
        const batch = tasksToCreate.slice(i, i + batchSize);
        const url = `${_config.baseUrl}${_config.tables.tasks}/batch/?user_field_names=true`;
        
        const response = await apiClient.makeRequest(url, {
            method: 'POST',
            body: JSON.stringify({ items: batch })
        });
        
        const newRecordsResponse = await response.json();
        let createdRecords = Array.isArray(newRecordsResponse) ? newRecordsResponse : 
                           newRecordsResponse.results || newRecordsResponse.items || [newRecordsResponse];
        
        createdRecords.forEach(record => {
            if (record && (record.id || record.Id)) {
                const newTask = {
                    Id: String(record.id || record.Id),
                    title: validateInput(record.Title || ''),
                    description: validateInput(record.Description || ''),
                    branch: validateInput(record.Branch || ''),
                    priority: validateInput(record.Priority || ''),
                    assignee: validateInput(record.Assignee || ''),
                    dueDate: validateInput(record['Due Date'] || '', 'date'),
                    status: validateInput(record.Status || 'Pending'),
                    userNote: validateInput(record['User Note'] || '')
                };
                appState.allTasks.push(newTask);
            }
        });
    }
    
    showNotification(`${tasksToCreate.length} tasks created successfully!`, 'success');
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

// Enhanced event handling
document.addEventListener('click', function(e) {
    const modals = ['taskModal', 'taskDetailModal', 'completeTaskModal'];
    modals.forEach(modalId => {
        const modal = document.getElementById(modalId);
        if (e.target === modal) {
            modal.classList.remove('show');
        }
    });
});

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        ['taskModal', 'taskDetailModal', 'completeTaskModal'].forEach(modalId => {
            document.getElementById(modalId).classList.remove('show');
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

// Additional security measures
(function() {
    'use strict';
    
    // Disable console in production (basic deterrent)
    if (!appState.debugMode && window.location.hostname !== 'localhost') {
        console.log = console.warn = console.error = function() {};
    }
    
    // Basic anti-tampering
    Object.freeze(_config);
    Object.freeze(ADMIN_CONFIG);
})();

