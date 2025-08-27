// ****************************************************************************************************
// ****************************************************************************************************
// **                                                                                              **
// **                            🚨 CRITICAL SECURITY WARNING 🚨                                   **
// **                                                                                              **
// ** This client-side approach is FUNDAMENTALLY INSECURE for production use.                      **
// ** API keys and sensitive data are visible to anyone who inspects the source code.              **
// **                                                                                              **
// ** FOR PRODUCTION: Implement a secure backend server to handle all API calls                    **
// ** and store sensitive credentials server-side only.                                            // **
// **                                                                                              **
// ** Current implementation is for DEVELOPMENT/DEMO purposes ONLY.                                **
// **                                                                                              **
// ****************************************************************************************************
// ****************************************************************************************************

// Enhanced configuration with multiple layers of obfuscation
const _config = (() => {
    const parts = ['19pWWNEBYlep9VU6gT', 'cYDknYzzrefKoN'];
    const base = 'aHR0cHM6Ly9hcGkuYmFzZXJvdy5pby9hcGkvZGF0YWJhc2Uvcm93cy90YWJsZS8=';

    return {
        getKey: () => parts.join(''),
        getBase: () => atob(base),
        dbId: '276777',
        tables: {
            u: '647091', // Users table ID
            t: '647088'  // Tasks table ID
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
    debugMode: false,
    availableFields: [],
    userFields: [],
    currentDetailTaskId: null,
    activeTab: 'active',
    taskIdToComplete: null,
    securityLevel: 'high',
    currentViewMode: 'grid', // Added for view mode toggle
    totalUsersCount: 0, // Track total users loaded
    taskCreationProgress: 0 // Track task creation progress
};

// Enhanced security monitoring
const SecurityMonitor = {
    devToolsOpen: false,
    networkTabActive: false,
    consoleCleared: 0,

    init() {
        this.detectDevTools();
        this.disableRightClick();
        this.disableKeyboardShortcuts();
        this.monitorNetworkTab();
        this.clearConsoleRegularly();
    },

    detectDevTools() {
        let devtools = {
            open: false,
            orientation: null
        };

        const threshold = 160;

        setInterval(() => {
            if (window.outerHeight - window.innerHeight > threshold ||
                window.outerWidth - window.innerWidth > threshold) {
                if (!devtools.open) {
                    devtools.open = true;
                    this.devToolsOpen = true;
                    this.handleDevToolsDetected();
                }
            } else {
                devtools.open = false;
                this.devToolsOpen = false;
            }
        }, 100);
    },

    handleDevToolsDetected() {
        if (!appState.debugMode) {
            // Clear console immediately
            console.clear();

            // Clear all stored data
            appState.users = [];
            appState.allTasks = [];

            // Show warning
            setTimeout(() => {
                alert('⚠️ Security Warning: Developer tools detected. Application data has been cleared for security.');
            }, 100);

            // Clear console again after alert
            setTimeout(() => {
                console.clear();
            }, 500);
        }
    },

    disableRightClick() {
        document.addEventListener('contextmenu', (e) => {
            if (!appState.debugMode) {
                e.preventDefault();
                return false;
            }
        });
    },

    disableKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            if (!appState.debugMode) {
                // Disable F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U
                if (e.key === 'F12' ||
                    (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J')) ||
                    (e.ctrlKey && e.key === 'U')) {
                    e.preventDefault();
                    this.handleDevToolsDetected();
                    return false;
                }
            }
        });
    },

    monitorNetworkTab() {
        // Override fetch to detect network monitoring
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
            if (SecurityMonitor.devToolsOpen && !appState.debugMode) {
                SecurityMonitor.clearSensitiveData();
            }
            return originalFetch.apply(this, args);
        };
    },

    clearConsoleRegularly() {
        setInterval(() => {
            if (!appState.debugMode && this.devToolsOpen) {
                console.clear();
                this.consoleCleared++;
            }
        }, 1000);
    },

    clearSensitiveData() {
        appState.users = [];
        appState.allTasks = [];
        sessionStorage.clear();
    }
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
        this.rateLimitDelay = 200;
    }

    async makeRequest(endpoint, options = {}) {
        // Security check
        if (SecurityMonitor.devToolsOpen && !appState.debugMode) {
            throw new Error('Access denied for security reasons');
        }

        // Rate limiting
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
                throw new Error(`Request failed: ${response.status}`);
            }

            return response;
        } catch (error) {
            throw error;
        }
    }
}

const apiClient = new SecureApiClient();

// Security-enhanced user defaults
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

// Initialize application with enhanced security
document.addEventListener('DOMContentLoaded', function() {
    SecurityMonitor.init();
    initializeApp();
});

async function initializeApp() {
    try {
        showNotification('Initializing application...', 'info');
        await loadAllUsers(); // Changed to loadAllUsers
        setupEventListeners();
        checkSavedLogin();
        showNotification('Application initialized successfully', 'success');
    } catch (error) {
        showNotification('Failed to initialize application', 'error');
    }
}

// Enhanced user loading with FULL pagination support for ALL 400+ users
async function loadAllUsers() {
    try {


        let allFetchedUsers = [];
        let page = 1;
        const size = 200; // Maximum per request
        let hasMoreData = true;

        while (hasMoreData) {
            const url = `${_config.getBase()}${_config.tables.u}/?user_field_names=true&size=${size}&page=${page}`;

            console.log(`Fetching users - Page: ${page}, Size: ${size}`);

            const response = await apiClient.makeRequest(url);
            const data = await response.json();

            if (data.results && data.results.length > 0) {
                allFetchedUsers = allFetchedUsers.concat(data.results);
                console.log(`Loaded ${data.results.length} users from page ${page}. Total so far: ${allFetchedUsers.length}`);

                // Check if there's more data
                if (!data.next || data.results.length < size) {
                    hasMoreData = false;
                } else {
                    page++;
                }
            } else {
                hasMoreData = false;
            }

            // Small delay to avoid rate limiting
            await new Promise(resolve => setTimeout(resolve, 100));
        }

        if (allFetchedUsers.length > 0) {
            appState.userFields = Object.keys(allFetchedUsers[0]);

            // Process users with enhanced security
            const processedUsers = [];
            for (const record of allFetchedUsers) {
                const username = validateInput(record.Username || record.username || '', 'username');
                const password = validateInput(record.Password || record.password || '');
                const role = validateInput(record.Role || record.role || 'user').toLowerCase();
                const fullName = validateInput(record.FullName || record['Full Name'] || username);

                if (username && password) {
                    processedUsers.push({
                        Id: record.id || record.Id,
                        username,
                        password: createSecureHash(password),
                        role,
                        fullName
                    });
                }
            }

            appState.users = processedUsers;
            appState.totalUsersCount = processedUsers.length;

            // Clear the response data immediately
            allFetchedUsers = null;

            console.log(`Successfully loaded ${appState.totalUsersCount} users total`);


        } else {
            throw new Error('No users found');
        }
    } catch (error) {
        console.error('Error loading users:', error);
        appState.users = getDefaultUsers();
        appState.totalUsersCount = appState.users.length;

    }
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

// Enhanced task loading with data protection and pagination
async function loadTasks() {
    document.getElementById('loadingSpinner').classList.remove('hidden');
    document.getElementById('tasksContainer').innerHTML = '';
    document.getElementById('tasksListContainer').innerHTML = ''; // Clear list container too

    let allFetchedTasks = [];
    let page = 1; // Baserow uses 'page' parameter for pagination
    const size = 200; // Baserow's default limit per request, adjust if needed
    let hasMoreData = true;

    try {
        while (hasMoreData) {
            // Construct the URL with 'page' and 'size' parameters
            const url = `${_config.getBase()}${_config.tables.t}/?user_field_names=true&size=${size}&page=${page}`;

            console.log(`Fetching tasks - Page: ${page}, Size: ${size}`);

            const response = await apiClient.makeRequest(url);
            const data = await response.json();

            if (data.results && data.results.length > 0) {
                allFetchedTasks = allFetchedTasks.concat(data.results);

                // Check if there's a 'next' URL or if the number of results is less than 'size'
                // If data.next is null or undefined, it means no more pages.
                // If data.results.length < size, it means this is the last page.
                if (!data.next || data.results.length < size) {
                    hasMoreData = false;
                } else {
                    page++; // Increment page for the next request
                }
            } else {
                // No more results, break the loop
                hasMoreData = false;
            }

            // Add a small delay to avoid hitting rate limits, especially for many requests
            await new Promise(resolve => setTimeout(resolve, 100));
        }

        if (allFetchedTasks.length > 0) {
            appState.availableFields = Object.keys(allFetchedTasks[0]);

            // Process tasks with enhanced security
            const processedTasks = [];
            for (const record of allFetchedTasks) {
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

            appState.allTasks = processedTasks;

            // Clear the response data immediately
            allFetchedTasks = null; // Clear the array to free memory

            showNotification('Tasks loaded successfully!', 'success');
        } else {
            // If no tasks are found after pagination, use demo data
            throw new Error('No tasks found from Baserow. Using demo data.');
        }
    } catch (error) {
        showNotification(`Failed to load tasks: ${error.message}. Using demo data.`, 'warning');
        appState.allTasks = generateDemoTasks();
    }

    document.getElementById('loadingSpinner').classList.add('hidden');
    filterTasks();
    updateStats();
    renderTasks();
    populateFilters();
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
        const isEdit = taskId && !taskId.startsWith('demo');

        const title = validateInput(document.getElementById('taskTitle').value, 'text', 200);
        if (!title.trim()) {
            throw new Error('Task title is required');
        }

        if (isEdit) {
            await updateExistingTask(taskId);
        } else {
            if (appState.currentUser.role !== 'admin') {
                throw new Error('Only administrators can create new tasks');
            }
            await createNewTasks(); // Renamed function
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

function generateDemoTasks() {
    const now = new Date();
    const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const twoDaysAgo = new Date(now.getTime() - 2 * 24 * 60 * 60 * 1000);

    return [
        {
            Id: 'demo1',
            title: 'Daily Inventory Check',
            description: 'Conduct daily inventory check for all departments',
            branch: 'C001',
            priority: 'High',
            assignee: 'Administrator',
            dueDate: '2024-01-20',
            status: 'Pending',
            userNote: '',
            createdAt: yesterday.toISOString()
        },
        {
            Id: 'demo2',
            title: 'Daily Inventory Check',
            description: 'Conduct daily inventory check for all departments',
            branch: 'C002',
            priority: 'High',
            assignee: 'Administrator',
            dueDate: '2024-01-20',
            status: 'Completed',
            userNote: 'Completed successfully',
            createdAt: yesterday.toISOString()
        },
        {
            Id: 'demo3',
            title: 'Daily Inventory Check',
            description: 'Conduct daily inventory check for all departments',
            branch: 'C003',
            priority: 'High',
            assignee: 'Administrator',
            dueDate: '2024-01-20',
            status: 'Pending',
            userNote: '',
            createdAt: yesterday.toISOString()
        },
        {
            Id: 'demo4',
            title: 'Weekly Sales Report',
            description: 'Generate and submit weekly sales report',
            branch: 'C001',
            priority: 'Medium',
            assignee: 'Administrator',
            dueDate: '2024-01-22',
            status: 'In Progress',
            userNote: '',
            createdAt: twoDaysAgo.toISOString()
        },
        {
            Id: 'demo5',
            title: 'Weekly Sales Report',
            description: 'Generate and submit weekly sales report',
            branch: 'C002',
            priority: 'Medium',
            assignee: 'Administrator',
            dueDate: '2024-01-22',
            status: 'Completed',
            userNote: 'Report submitted',
            createdAt: twoDaysAgo.toISOString()
        },
        {
            Id: 'demo6',
            title: 'Store Maintenance',
            description: 'Perform routine store maintenance tasks',
            branch: 'C001',
            priority: 'Low',
            assignee: 'Administrator',
            dueDate: '2024-01-25',
            status: 'Pending',
            userNote: '',
            createdAt: now.toISOString()
        }
    ];
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
    const reportsButton = document.getElementById('reportsButton'); // Get reports button

    if (appState.currentUser.role === 'admin') {
        adminControls.classList.remove('hidden');
        filterControls.classList.remove('hidden');
        userTabs.classList.add('hidden');
        viewModeControls.classList.add('hidden'); // Hide view mode controls for admin
        reportsButton.classList.remove('hidden'); // Show reports button for admin

        // Admin always uses list view
        document.getElementById('tasksContainer').classList.add('hidden'); // Hide grid for admin
        document.getElementById('tasksListContainer').classList.remove('hidden'); // Show list for admin

        ['branchFilter', 'userFilter', 'statusFilter', 'priorityFilter'].forEach(id => {
            document.getElementById(id).addEventListener('change', filterTasks);
        });

        // Show user count in admin panel
        updateAdminUserInfo();
    } else {
        adminControls.classList.add('hidden');
        filterControls.classList.add('hidden');
        userTabs.classList.remove('hidden');
        viewModeControls.classList.remove('hidden'); // Show view mode controls for user
        reportsButton.classList.add('hidden'); // Hide reports button for non-admin

        // Default to grid view for users, but allow toggle
        document.getElementById('tasksContainer').classList.remove('hidden');
        document.getElementById('tasksListContainer').classList.add('hidden');
        setViewMode('grid'); // Ensure user starts in grid view
    }

    loadTasks();
}

// New function to update admin user info
function updateAdminUserInfo() {
    const userInfoEl = document.getElementById('adminUserInfo');
    if (userInfoEl) {
        const nonAdminUsers = appState.users.filter(user => user.role !== 'admin');
        userInfoEl.textContent = `Total Users: ${appState.totalUsersCount} | Non-Admin: ${nonAdminUsers.length}`;
    }
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
    const inProgress = tasksToCount.filter(task => task.status === 'In Progress').length;
    const completed = tasksToCount.filter(task => task.status === 'Completed').length;
    const overdue = tasksToCount.filter(task =>
        task.status !== 'Completed' && new Date(task.dueDate) < new Date()
    ).length;

    document.getElementById('totalTasks').textContent = total;
    document.getElementById('pendingTasks').textContent = pending;
    document.getElementById('completedTasks').textContent = completed;
    document.getElementById('overdueTasks').textContent = overdue;
    document.getElementById('inProgress').textContent = inProgress;
}

// NEW: Function to filter tasks based on stat card clicks
function filterTasksByStat(statType) {
    // Start with all tasks relevant to the current user's scope
    let baseTasks = [];
    if (appState.currentUser && appState.currentUser.role === 'admin') {
        baseTasks = appState.allTasks;
        // Clear existing filters for admin when using stat cards
        clearAllFilters();
    } else {
        const username = appState.currentUser.username;
        const existingBranches = [...new Set(appState.allTasks.map(task => task.branch).filter(b => b))];
        const isBranchUser = existingBranches.includes(username);

        if (isBranchUser) {
            baseTasks = appState.allTasks.filter(task => task.branch === username);
        } else {
            baseTasks = appState.allTasks.filter(task =>
                task.assignee === appState.currentUser.fullName ||
                task.assignee === appState.currentUser.username
            );
        }
    }

    let filteredByStat = [];

    switch (statType) {
        case 'total':
            filteredByStat = baseTasks;
            break;
        case 'pending':
            filteredByStat = baseTasks.filter(task => task.status === 'Pending');
            // For admin, also set the status filter dropdown
            if (appState.currentUser && appState.currentUser.role === 'admin') {
                document.getElementById('statusFilter').value = 'Pending';
            }
            break;
        case 'inProgress': // ADD THIS CASE
            filteredByStat = baseTasks.filter(task => task.status === 'In Progress');
            if (appState.currentUser && appState.currentUser.role === 'admin') {
                document.getElementById('statusFilter').value = 'In Progress';
            }
            break;
        case 'completed':
            filteredByStat = baseTasks.filter(task => task.status === 'Completed');
            // For admin, also set the status filter dropdown
            if (appState.currentUser && appState.currentUser.role === 'admin') {
                document.getElementById('statusFilter').value = 'Completed';
            }
            break;
        case 'overdue':
            filteredByStat = baseTasks.filter(task =>
                task.status !== 'Completed' && new Date(task.dueDate) < new Date()
            );
            // For admin, also set the status filter dropdown
            if (appState.currentUser && appState.currentUser.role === 'admin') {
                document.getElementById('statusFilter').value = 'Overdue';
            }
            break;
    }

    appState.filteredTasks = filteredByStat; // Update the global filteredTasks
    updateStats(); // Recalculate stats based on the new filteredTasks
    renderTasks(); // Re-render the tasks
    updateFilterSummary(); // Update filter summary for admin
    showNotification(`Filtered by ${statType} tasks.`, 'info');
}

// NEW: Function to download reports with proper Arabic/Unicode support
function downloadReport(type) {
    if (appState.currentUser.role !== 'admin') {
        showNotification('Only administrators can download reports.', 'warning');
        return;
    }

    let tasksToReport = [];
    let fileName = 'tasks_report.csv';

    switch (type) {
        case 'total':
            tasksToReport = appState.allTasks;
            fileName = 'total_tasks_report.csv';
            break;
        case 'pending':
            tasksToReport = appState.allTasks.filter(task => task.status === 'Pending');
            fileName = 'pending_tasks_report.csv';
            break;
        case 'inProgress': // ADD THIS CASE FOR IN PROGRESS
            tasksToReport = appState.allTasks.filter(task => task.status === 'In Progress');
            fileName = 'in_progress_tasks_report.csv';
            break;
        case 'completed':
            tasksToReport = appState.allTasks.filter(task => task.status === 'Completed');
            fileName = 'completed_tasks_report.csv';
            break;
        case 'overdue':
            tasksToReport = appState.allTasks.filter(task =>
                task.status !== 'Completed' && new Date(task.dueDate) < new Date()
            );
            fileName = 'overdue_tasks_report.csv';
            break;
        default:
            showNotification('Invalid report type.', 'error');
            return;
    }

    if (tasksToReport.length === 0) {
        showNotification('No tasks to report for this category.', 'info');
        return;
    }

    const headers = ['Id', 'Title', 'Description', 'Branch', 'Priority', 'Assignee', 'Due Date', 'Status', 'User Note', 'Created At'];
    const csvRows = [];
    csvRows.push(headers.join(',')); // Add headers

    tasksToReport.forEach(task => {
        const row = [
            `"${task.Id || ''}"`,
            `"${(task.title || '').replace(/"/g, '""')}"`, // Escape double quotes
            `"${(task.description || '').replace(/"/g, '""')}"`,
            `"${(task.branch || '').replace(/"/g, '""')}"`,
            `"${(task.priority || '').replace(/"/g, '""')}"`,
            `"${(task.assignee || '').replace(/"/g, '""')}"`,
            `"${task.dueDate || ''}"`,
            `"${(task.status || '').replace(/"/g, '""')}"`,
            `"${(task.userNote || '').replace(/"/g, '""')}"`,
            `"${task.createdAt || ''}"`
        ];
        csvRows.push(row.join(','));
    });

    const csvString = csvRows.join('\n');
    
    // CRITICAL FIX: Add BOM (Byte Order Mark) for proper UTF-8 encoding
    // This ensures Arabic and other Unicode characters display correctly
    const BOM = '\uFEFF';
    const csvWithBOM = BOM + csvString;
    
    // CRITICAL FIX: Specify UTF-8 encoding explicitly
    const blob = new Blob([csvWithBOM], { 
        type: 'text/csv;charset=utf-8;' 
    });
    
    const link = document.createElement('a');
    if (link.download !== undefined) { // FIXED: Added 'undefined' check
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', fileName);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        // Clean up the URL object
        setTimeout(() => {
            URL.revokeObjectURL(url);
        }, 100);
        
        showNotification(`Report "${fileName}" downloaded successfully!`, 'success');
    } else {
        // Fallback for browsers that don't support download attribute
        const url = URL.createObjectURL(blob);
        window.open(url, '_blank');
        showNotification('Report opened in new tab. Please save the file manually.', 'info');
        
        // Clean up the URL object
        setTimeout(() => {
            URL.revokeObjectURL(url);
        }, 1000);
    }
}

// NEW: Open Report Download Modal
function openReportDownloadModal() {
    if (appState.currentUser && appState.currentUser.role === 'admin') {
        document.getElementById('reportDownloadModal').classList.add('show');
    } else {
        showNotification('You do not have permission to download reports.', 'error');
    }
}

// NEW: Close Report Download Modal
function closeReportDownloadModal() {
    document.getElementById('reportDownloadModal').classList.remove('show');
}

// NEW: Open Report Download Modal
function openReportDownloadModal() {
    if (appState.currentUser && appState.currentUser.role === 'admin') {
        document.getElementById('reportDownloadModal').classList.add('show');
    } else {
        showNotification('You do not have permission to download reports.', 'error');
    }
}

// NEW: Close Report Download Modal
function closeReportDownloadModal() {
    document.getElementById('reportDownloadModal').classList.remove('show');
}

// NEW: Helper function to update task status
async function updateTaskStatus(taskId, newStatus, userNote = '') {
    try {
        if (taskId.startsWith('demo')) {
            const task = findTaskById(taskId);
            if (task) {
                task.status = newStatus;
                task.userNote = userNote;
            }
            filterTasks();
            updateStats();
            return;
        }

        const url = `${_config.getBase()}${_config.tables.t}/${taskId}/?user_field_names=true`;
        const response = await apiClient.makeRequest(url, {
            method: 'PATCH',
            body: JSON.stringify({
                'Status': newStatus,
                'User Note': userNote
            })
        });

        const updatedRecord = await response.json();
        const task = findTaskById(taskId);
        if (task) {
            task.status = newStatus;
            task.userNote = userNote;
        }
        filterTasks();
        updateStats();
    } catch (error) {
        console.error(`Failed to update task status for ${taskId}:`, error);
        showNotification(`Failed to update task status: ${error.message}`, 'error');
    }
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
            if (!task.Id.startsWith('demo')) {
                const url = `${_config.getBase()}${_config.tables.t}/${task.Id}/`;
                await apiClient.makeRequest(url, { method: 'DELETE' });
            }
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
    appState.debugMode = !appState.debugMode;
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

        // Update the checkbox text to show the actual count
        const nonAdminUsers = appState.users.filter(user => user.role !== 'admin');
        const checkboxLabel = document.querySelector('label[for="assignToAllNonAdminUsersCheckbox"]');
        if (checkboxLabel) {
            checkboxLabel.textContent = `Assign to all non-admin users (${nonAdminUsers.length} users)`;
        }
    } else {
        userNoteField.classList.remove('hidden');
        assignToAllNonAdminUsersContainer.classList.add('hidden'); // Hide for non-admin or editing existing task
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

    // NEW: If the current user is not an admin and the task is Pending,
    // change its status to "In Progress" and update it in the backend.
    if (appState.currentUser && appState.currentUser.role !== 'admin' && task.status === 'Pending') {
        updateTaskStatus(taskId, 'In Progress', task.userNote); // Pass existing note
        task.status = 'In Progress'; // Update local state immediately for responsiveness
        showNotification('Task status updated to In Progress!', 'info');
    }

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
        }

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
        if (!taskId.startsWith('demo')) {
            const url = `${_config.getBase()}${_config.tables.t}/${taskId}/`;
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
        showNotification(`Failed to delete task: ${error.message}`, 'error');
    }
}

// UPDATED: Enhanced function to create tasks for ALL 400+ users with progress tracking
async function createNewTasks() { // Renamed from createNewTasksForAllUsers
    const assignToAllNonAdmin = document.getElementById('assignToAllNonAdminUsersCheckbox').checked;
    let tasksToCreate = [];

    const inputBranches = validateInput(document.getElementById('taskBranch').value);
    const branches = inputBranches.split(',').map(b => b.trim()).filter(b => b);

    if (assignToAllNonAdmin) {
        const nonAdminUsers = appState.users.filter(user => user.role !== 'admin');

        if (nonAdminUsers.length === 0) {
            throw new Error('No non-admin users found to assign tasks to.');
        }

        console.log(`Creating tasks for ${nonAdminUsers.length} non-admin users`);
        showNotification(`Preparing to create tasks for ${nonAdminUsers.length} users...`, 'info');

        const adminAssignee = appState.currentUser.fullName || appState.currentUser.username;

        nonAdminUsers.forEach(user => {
            // If assigning to all non-admin users, each user gets a task for their own branch (username)
            // If the task has specific branches, we'll create for those branches for each user.
            // For simplicity, let's assume if "assign to all" is checked, it's for their own branch.
            // If you want to assign to specific branches for ALL non-admin users, this logic needs adjustment.
            // For now, if "assign to all" is checked, it overrides the branch input for individual tasks.
            tasksToCreate.push(getValidatedTaskDataForUser(adminAssignee, user.username));
        });
    } else {
        if (branches.length === 0) {
            throw new Error('Please enter at least one branch.');
        }
        const assignee = appState.currentUser.fullName || appState.currentUser.username;
        branches.forEach(branch => {
            tasksToCreate.push(getValidatedTaskDataForUser(assignee, branch));
        });
    }

    // Progress tracking
    let createdCount = 0;
    const totalTasks = tasksToCreate.length;

    // Create progress notification
    const progressNotification = document.createElement('div');
    progressNotification.className = 'fixed top-20 right-4 z-50 bg-blue-100 border-l-4 border-blue-500 p-4 rounded-lg shadow-lg';
    progressNotification.innerHTML = `
        <div class="flex items-center">
            <div class="loading-spinner mr-3"></div>
            <div>
                <div class="font-medium text-blue-800">Creating Tasks...</div>
                <div class="text-blue-600 text-sm">
                    <span id="taskProgress">0</span> / ${totalTasks} tasks created
                </div>
                <div class="w-64 bg-blue-200 rounded-full h-2 mt-2">
                    <div id="progressBar" class="bg-blue-600 h-2 rounded-full" style="width: 0%"></div>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(progressNotification);

    const updateProgress = (current) => {
        const progressText = document.getElementById('taskProgress');
        const progressBar = document.getElementById('progressBar');
        if (progressText) progressText.textContent = current;
        if (progressBar) {
            const percentage = (current / totalTasks) * 100;
            progressBar.style.width = `${percentage}%`;
        }
    };

    try {
        const batchSize = 20;

        for (let i = 0; i < tasksToCreate.length; i += batchSize) {
            const batch = tasksToCreate.slice(i, i + batchSize);

            try {
                const url = `${_config.getBase()}${_config.tables.t}/batch/?user_field_names=true`;

                const response = await apiClient.makeRequest(url, {
                    method: 'POST',
                    body: JSON.stringify({ items: batch })
                });

                const newRecordsResponse = await response.json();
                let createdRecords = Array.isArray(newRecordsResponse) ? newRecordsResponse :
                                   newRecordsResponse.results || newRecordsResponse.items || [newRecordsResponse];

                if (Array.isArray(createdRecords)) {
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
                                userNote: validateInput(record['User Note'] || ''),
                                createdAt: record.created_at || record.Created_At || new Date().toISOString()
                            };
                            appState.allTasks.push(newTask);
                            createdCount++;
                            updateProgress(createdCount);
                        }
                    });
                }
            } catch (batchError) {
                console.error(`Error creating batch ${Math.floor(i/batchSize) + 1}:`, batchError);
                showNotification(`Warning: Some tasks in batch ${Math.floor(i/batchSize) + 1} failed to create`, 'warning');
            }

            await new Promise(resolve => setTimeout(resolve, 500));
        }

        document.body.removeChild(progressNotification);

        if (createdCount > 0) {
            showNotification(`Successfully created ${createdCount} out of ${totalTasks} tasks!`, 'success');
        } else {
            throw new Error('No tasks were created successfully');
        }

    } catch (error) {
        if (document.body.contains(progressNotification)) {
            document.body.removeChild(progressNotification);
        }

        console.error('Task creation error:', error);
        throw new Error(`Failed to create tasks: ${error.message}`);
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
        'Status': validateInput(document.getElementById('taskStatus').value || 'Pending'),
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
    const modals = ['taskModal', 'taskDetailModal', 'completeTaskModal', 'branchDetailsModal', 'reportDownloadModal'];
    modals.forEach(modalId => {
        const modal = document.getElementById(modalId);
        if (modal && e.target === modal) {
            modal.classList.remove('show');
        }
    });
});

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        ['taskModal', 'taskDetailModal', 'completeTaskModal', 'branchDetailsModal', 'reportDownloadModal'].forEach(modalId => {
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

// Initialize enhanced security measures
(function() {
    'use strict';

    // Aggressive console clearing
    const originalConsole = {
        log: console.log,
        warn: console.warn,
        error: console.error,
        info: console.info,
        debug: console.debug,
        trace: console.trace
    };

    if (window.location.hostname !== 'localhost' && !window.location.hostname.includes('127.0.0.1')) {
        console.log = console.warn = console.error = console.info = console.debug = console.trace = function() {};

        // Clear console every second
        setInterval(() => {
            console.clear();
        }, 1000);
    }

    // Prevent object inspection
    Object.freeze(_config);
    Object.freeze(ADMIN_CONFIG);
    Object.freeze(SecurityMonitor);

    // Additional anti-debugging measures
    let debuggerDetected = false;

    setInterval(() => {
        const start = new Date();
        debugger;
        const end = new Date();
        if (end - start > 100) {
            if (!debuggerDetected && !appState.debugMode) {
                debuggerDetected = true;
                SecurityMonitor.clearSensitiveData();
                alert('⚠️ Debugging detected. Application data cleared.');
            }
        } else {
            debuggerDetected = false;
        }
    }, 1000);

})();
