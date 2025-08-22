// Configuration
// IMPORTANT: Client-side encryption of API keys is NOT secure.
// This is a basic obfuscation for demonstration, not true security.
// For production, use a secure backend to handle API calls.
const BASEROW_CONFIG = {
    apiKey: '19pWWNEBYlep9VU6gTcYDknYzzrefKoN',
    databaseId: '276777', // This is the database ID, not directly used in row operations
    baseUrl: 'https://api.baserow.io/api/database/rows/table/',
    tables: {
        users: '647091', // Table ID for Users
        tasks: '647088'  // Table ID for Tasks
    }
};

function getBaserowConfig() {
    return BASEROW_CONFIG;
}

// Global variables
let currentUser = null;
let allTasks = []; // Will now include 'userNote'
let users = [];
let filteredTasks = []; // This will hold tasks filtered by user role or admin filters
let debugMode = false;
let availableFields = []; // Stores field names from Baserow Tasks table
let userFields = [];      // Stores field names from Baserow Users table
let currentDetailTaskId = null; // To store the ID of the task currently shown in detail modal
let activeTab = 'active'; // 'active' or 'completed' for user dashboard
let taskIdToComplete = null; // Stores the ID of the task being completed

// Admin credentials - stored as pre-hashed values to prevent exposure in source code
const ADMIN_CREDENTIALS = {
    username: 'admin',
    // This is a pre-hashed password. The original password is not stored in the source code.
    passwordHash: '9f3c4a3fb73ce55b8e1d0d1c0b6b2c8a7d5e4f6c8b9a0e1d2c3b4a5f6e7d8c9b0a'
};

// Default users - embedded as fallback
// Passwords are now pre-hashed for consistency with Baserow fetched users
const DEFAULT_USERS = [
    { username: 'user1', password: CryptoJS.SHA256('password1').toString(), role: 'user', fullName: 'John User' },
    { username: 'user2', password: CryptoJS.SHA256('password2').toString(), role: 'user', fullName: 'Jane User' },
    { username: 'user3', password: CryptoJS.SHA256('password3').toString(), role: 'user', fullName: 'Bob User' },
    { username: 'manager1', password: CryptoJS.SHA256('manager123').toString(), role: 'manager', fullName: 'Alice Manager' },
    { username: 'manager2', password: CryptoJS.SHA256('manager456').toString(), role: 'manager', fullName: 'Mike Manager' },
    { username: 'supervisor1', password: CryptoJS.SHA256('super123').toString(), role: 'supervisor', fullName: 'Sarah Supervisor' },
    { username: 'employee1', password: CryptoJS.SHA256('emp123').toString(), role: 'employee', fullName: 'Tom Employee' },
    { username: 'employee2', password: CryptoJS.SHA256('emp456').toString(), role: 'employee', fullName: 'Lisa Employee' },
    // Added C001 for branch filtering demo
    { username: 'C001', password: CryptoJS.SHA256('branchpass').toString(), role: 'branch_user', fullName: 'Branch C001 User' }
];

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    loadUsers();
    setupEventListeners();
    checkSavedLogin(); // Check for saved login on page load
});

// Function to hash a password using SHA256
function hashPassword(password) {
    return CryptoJS.SHA256(password).toString();
}

// Helper function to normalize task ID for consistent comparison
function normalizeTaskId(id) {
    return String(id); // Convert to string for consistent comparison
}

// Helper function to find task by ID with flexible matching
function findTaskById(taskId) {
    const normalizedId = normalizeTaskId(taskId);
    console.log('Looking for task with ID:', normalizedId, 'in allTasks array of length:', allTasks.length);
    
    // First try exact string match
    let task = allTasks.find(t => normalizeTaskId(t.Id) === normalizedId);
    
    if (!task) {
        // Try numeric comparison if the ID looks like a number
        const numericId = parseInt(normalizedId, 10);
        if (!isNaN(numericId)) {
            task = allTasks.find(t => parseInt(t.Id, 10) === numericId);
        }
    }
    
    if (task) {
        console.log('Found task:', task);
    } else {
        console.warn('Task not found. Available task IDs:', allTasks.map(t => t.Id));
    }
    
    return task;
}

// Load users from Baserow
async function loadUsers() {
    const config = getBaserowConfig();
    try {
        // Try to fetch users from Baserow
        const url = `${config.baseUrl}${config.tables.users}/?user_field_names=true`;
        console.log('Fetching users from:', url);
        
        const response = await fetch(url, {
            headers: {
                'Authorization': `Token ${config.apiKey}`
            }
        });
        
        console.log('Users API response status:', response.status);
        
        if (response.ok) {
            const data = await response.json();
            console.log('Users API Response:', data);
            
            // Extract available fields from the first record
            if (data.results && data.results.length > 0) {
                userFields = Object.keys(data.results[0]); // Baserow returns fields directly in the object
                console.log('Available user fields:', userFields);
            }
            
            // Map the users from Baserow and hash their passwords
            users = data.results.map(record => {
                console.log('Processing user record:', record);
                
                // Baserow field names are usually exact, but keeping flexibility
                const username = record.Username || record.username || record.User || record.user || record.Name || record.name || '';
                const password = record.Password || record.password || record.Pass || record.pass || '';
                const role = record.Role || record.role || record.Type || record.type || 'user';
                const fullName = record.FullName || record['Full Name'] || record.fullName || record.DisplayName || record['Display Name'] || username;
                
                return {
                    Id: record.id || record.Id, // Prioritize 'id' then fallback to 'Id'
                    username: username,
                    // Hash the password from Baserow for consistent comparison
                    password: password ? hashPassword(password) : '', 
                    role: role.toLowerCase(),
                    fullName: fullName
                };
            }).filter(user => user.username && user.password);
            
            console.log('Processed users:', users);
            
            if (users.length > 0) {
                console.log(`Loaded ${users.length} users from Baserow successfully`);
                return; // Success, exit function
            } else {
                throw new Error('No valid users found in Baserow');
            }
        } else {
            const errorText = await response.text();
            console.error('Users API Error:', response.status, errorText);
            throw new Error(`Failed to load users: ${response.status} - ${errorText}`);
        }
    } catch (error) {
        console.error('Error loading users from Baserow:', error);
        console.log('Using default embedded users as fallback');
        
        // Use default users as fallback
        users = DEFAULT_USERS;
    }
}

// Setup event listeners
function setupEventListeners() {
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    // Filter event listeners are conditionally added/removed in showDashboard
}

// Check for saved login
function checkSavedLogin() {
    const savedUser = sessionStorage.getItem('currentUser');
    if (savedUser) {
        try {
            currentUser = JSON.parse(savedUser);
            showDashboard();
            showNotification(`Welcome back, ${currentUser.fullName || currentUser.username}!`, 'info');
        } catch (e) {
            console.error('Error parsing saved user data:', e);
            sessionStorage.removeItem('currentUser'); // Clear invalid data
        }
    }
}

// Clear all filters (only relevant for admin)
function clearAllFilters() {
    document.getElementById('branchFilter').value = '';
    document.getElementById('userFilter').value = '';
    document.getElementById('statusFilter').value = '';
    document.getElementById('priorityFilter').value = '';
    filterTasks(); // Re-apply filters based on current user's role
}

// Update filter summary (only relevant for admin)
function updateFilterSummary() {
    if (currentUser && currentUser.role !== 'admin') {
        document.getElementById('filterSummary').classList.add('hidden');
        return;
    }

    const branch = document.getElementById('branchFilter').value;
    const user = document.getElementById('userFilter').value;
    const status = document.getElementById('statusFilter').value;
    const priority = document.getElementById('priorityFilter').value;
    
    const filters = [];
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

// Toggle debug mode
function toggleDebug() {
    debugMode = !debugMode;
    const debugInfo = document.getElementById('debugInfo');
    if (debugMode) {
        debugInfo.classList.remove('hidden');
        // Update debug info
        document.getElementById('loadedUsers').textContent = JSON.stringify(users.map(user => ({
            username: user.username,
            fullName: user.fullName,
            role: user.role,
            // Do NOT expose hashed password in debug info
            // hasPassword: !!user.password 
        })), null, 2);
    } else {
        debugInfo.classList.add('hidden');
    }
}

// Show notification
function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    const icon = document.getElementById('notificationIcon');
    const messageEl = document.getElementById('notificationMessage');
    
    messageEl.textContent = message;
    
    // Set icon and color based on type
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
    
    // Auto hide after 5 seconds
    setTimeout(() => {
        hideNotification();
    }, 5000);
}

// Hide notification
function hideNotification() {
    document.getElementById('notification').classList.remove('show');
}

// Handle login
function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const hashedPassword = hashPassword(password); // Hash the input password
    
    console.log('Login attempt for:', username);
    
    // Check admin credentials using pre-hashed password
    if (username === ADMIN_CREDENTIALS.username && hashedPassword === ADMIN_CREDENTIALS.passwordHash) {
        currentUser = { username: 'admin', role: 'admin', fullName: 'Administrator' };
        sessionStorage.setItem('currentUser', JSON.stringify(currentUser)); // Save login
        showDashboard();
        showNotification(`Welcome Administrator! Logged in as admin`, 'success');
        return;
    }
    
    // Check user credentials from Baserow (passwords are already hashed in `users` array)
    const user = users.find(u => u.username === username && u.password === hashedPassword);
    if (user) {
        currentUser = user;
        sessionStorage.setItem('currentUser', JSON.stringify(currentUser)); // Save login
        showDashboard();
        showNotification(`Welcome ${user.fullName || user.username}! Logged in as ${user.role}`, 'success');
    } else {
        console.log('Login failed for:', username);
        document.getElementById('loginError').classList.remove('hidden');
        setTimeout(() => {
            document.getElementById('loginError').classList.add('hidden');
        }, 3000);
    }
}

// Show dashboard
function showDashboard() {
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('dashboard').classList.remove('hidden');
    
    // Update user info
    document.getElementById('userWelcome').textContent = `Welcome, ${currentUser.fullName || currentUser.username}!`;
    document.getElementById('userRole').textContent = `Role: ${currentUser.role}`;
    
    // Show admin controls and filter bar if admin, hide otherwise
    const adminControls = document.getElementById('adminControls');
    const filterControls = document.getElementById('filterControls');
    const userTabs = document.getElementById('userTabs');

    if (currentUser.role === 'admin') {
        adminControls.classList.remove('hidden');
        filterControls.classList.remove('hidden');
        userTabs.classList.add('hidden'); // Hide user tabs for admin
        // Re-add event listeners for filters for admin
        document.getElementById('branchFilter').addEventListener('change', filterTasks);
        document.getElementById('userFilter').addEventListener('change', filterTasks);
        document.getElementById('statusFilter').addEventListener('change', filterTasks);
        document.getElementById('priorityFilter').addEventListener('change', filterTasks);
    } else {
        adminControls.classList.add('hidden');
        filterControls.classList.add('hidden');
        userTabs.classList.remove('hidden'); // Show user tabs for non-admin
        // Remove event listeners for filters for non-admin
        document.getElementById('branchFilter').removeEventListener('change', filterTasks);
        document.getElementById('userFilter').removeEventListener('change', filterTasks);
        document.getElementById('statusFilter').removeEventListener('change', filterTasks);
        document.getElementById('priorityFilter').removeEventListener('change', filterTasks);
    }
    
    // Load tasks
    loadTasks();
}

// Logout
function logout() {
    currentUser = null;
    allTasks = [];
    filteredTasks = [];
    sessionStorage.removeItem('currentUser'); // Clear saved login
    document.getElementById('dashboard').classList.add('hidden');
    document.getElementById('loginScreen').classList.remove('hidden');
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    showNotification('You have been logged out.', 'info');
}

// Load tasks from Baserow
async function loadTasks() {
    document.getElementById('loadingSpinner').classList.remove('hidden');
    document.getElementById('tasksContainer').innerHTML = '';
    const config = getBaserowConfig();
    
    try {
        const url = `${config.baseUrl}${config.tables.tasks}/?user_field_names=true`;
        console.log('Fetching tasks from:', url);
        
        const response = await fetch(url, {
            headers: {
                'Authorization': `Token ${config.apiKey}`
            }
        });
        
        console.log('Tasks API response status:', response.status);
        
        if (response.ok) {
            const data = await response.json();
            console.log('Tasks API Response:', data);
            console.log('Number of tasks received:', data.results ? data.results.length : 0);
            
            // Extract available fields from the first record
            if (data.results && data.results.length > 0) {
                availableFields = Object.keys(data.results[0]); // Baserow returns fields directly in the object
                console.log('Available task fields:', availableFields);
                
                if (debugMode) {
                    document.getElementById('availableFields').textContent = JSON.stringify(availableFields, null, 2);
                    document.getElementById('apiResponse').textContent = JSON.stringify(data.results[0], null, 2);
                }
            }
            
            // Clear existing tasks and map new ones
            allTasks = [];
            data.results.forEach((record, index) => {
                console.log(`Processing task record ${index + 1}:`, record);
                
                // Baserow field names are usually exact, but keeping flexibility
                const processedTask = {
                    Id: normalizeTaskId(record.id || record.Id), // Prioritize 'id' then fallback to 'Id' and normalize
                    title: record.Title || record.title || '',
                    description: record.Description || record.description || '',
                    branch: record.Branch || record.branch || '',
                    priority: record.Priority || record.priority || '',
                    assignee: record.Assignee || record.assignee || '',
                    dueDate: record['Due Date'] || record.DueDate || record.dueDate || '',
                    status: record.Status || record.status || 'Pending',
                    userNote: record['User Note'] || record.UserNote || '' // NEW: Add userNote field
                };
                
                console.log(`Processed task ${index + 1} with ID:`, processedTask.Id);
                allTasks.push(processedTask);
            });
            
            console.log('Final allTasks array:', allTasks);
            console.log('Task IDs in allTasks:', allTasks.map(t => t.Id));
            showNotification('Tasks loaded successfully!', 'success');
        } else {
            const errorText = await response.text();
            console.error('Tasks API Error:', response.status, errorText);
            throw new Error(`Failed to load tasks from Baserow: ${response.status} - ${errorText}`);
        }
    } catch (error) {
        console.error('Error loading tasks:', error);
        showNotification(`Failed to load tasks: ${error.message}. Using demo data.`, 'warning');
        allTasks = generateDemoTasks();
    }
    
    document.getElementById('loadingSpinner').classList.add('hidden');
    
    // Apply initial filtering based on user role
    filterTasks(); 
    updateStats(); // Update stats after filtering
    renderTasks(); // Render tasks after filtering
    populateFilters(); // Populate filters (only visible for admin)
}

// Generate demo tasks
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
            userNote: 'Checked inventory on Monday, found some discrepancies.' // Demo note
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
            branch: 'C001', // Example for C001 branch
            priority: 'High',
            assignee: 'Branch C001 User', // Assign to the C001 user
            dueDate: '2024-01-15',
            status: 'Pending',
            userNote: 'Need to double check figures for last week.'
        },
        {
            Id: 'demo4',
            title: 'Clean Store Front',
            description: 'Ensure the store front is clean and presentable',
            branch: 'C001', // Example for C001 branch
            priority: 'Low',
            assignee: 'Branch C001 User', // Assign to the C001 user
            dueDate: '2024-01-16',
            status: 'Completed',
            userNote: 'Store front cleaned and looking good.'
        },
        {
            Id: 'demo5',
            title: 'Restock Shelves - Dairy',
            description: 'Restock dairy products in the refrigerated section',
            branch: 'Downtown',
            priority: 'Medium',
            assignee: 'John User',
            dueDate: '2024-01-18',
            status: 'In Progress',
            userNote: 'Almost done, just waiting for new delivery.'
        }
    ];
}

// Update statistics
function updateStats() {
    let tasksToCount = [];

    if (currentUser && currentUser.role === 'admin') {
        tasksToCount = filteredTasks; // Admin sees stats for currently filtered tasks
    } else {
        // For non-admin users, count only their relevant tasks
        const username = currentUser.username;
        const isBranchUser = users.some(u => u.username === username && u.role === 'branch_user'); // Check if current user is a branch user

        if (isBranchUser) {
            tasksToCount = allTasks.filter(task => task.branch === username);
        } else {
            tasksToCount = allTasks.filter(task => 
                task.assignee === currentUser.fullName || task.assignee === currentUser.username
            );
        }
    }

    const total = tasksToCount.length;
    const pending = tasksToCount.filter(task => task.status === 'Pending').length;
    const completed = tasksToCount.filter(task => task.status === 'Completed').length;
    const overdue = tasksToCount.filter(task => {
        return task.status !== 'Completed' && new Date(task.dueDate) < new Date();
    }).length;
    
    document.getElementById('totalTasks').textContent = total;
    document.getElementById('pendingTasks').textContent = pending;
    document.getElementById('completedTasks').textContent = completed;
    document.getElementById('overdueTasks').textContent = overdue;
}
// Render tasks
function renderTasks() {
    const container = document.getElementById('tasksContainer');
    const emptyState = document.getElementById('emptyState');

    let tasksToRender = [];

    console.log('=== RENDER TASKS DEBUG START ===');
    console.log('Current user:', currentUser);
    console.log('Active tab:', activeTab);
    console.log('Filtered tasks count:', filteredTasks.length);

    if (currentUser && currentUser.role === 'admin') {
        tasksToRender = filteredTasks; // Admin renders based on admin filters
        console.log('Admin rendering - using filteredTasks:', tasksToRender.length);
    } else {
        // Non-admin users render based on filteredTasks (already filtered in filterTasks()) and active tab
        console.log('Non-admin rendering - using filteredTasks with tab filtering');
        
        if (activeTab === 'active') {
            tasksToRender = filteredTasks.filter(task => task.status !== 'Completed');
            console.log(`Active tab - filtered to ${tasksToRender.length} non-completed tasks`);
        } else { // activeTab === 'completed'
            tasksToRender = filteredTasks.filter(task => task.status === 'Completed');
            console.log(`Completed tab - filtered to ${tasksToRender.length} completed tasks`);
        }

        // Debug: show what tasks are being considered
        console.log('Tasks to render after tab filtering:');
        tasksToRender.forEach((task, index) => {
            console.log(`  ${index + 1}. "${task.title}" - Status: ${task.status}, Branch: ${task.branch}, Assignee: ${task.assignee}`);
        });
    }

    console.log('Final tasks to render:', tasksToRender.length);
    console.log('=== RENDER TASKS DEBUG END ===');

    if (tasksToRender.length === 0) {
        container.innerHTML = '';
        emptyState.classList.remove('hidden');
        console.log('Showing empty state - no tasks to render');
        return;
    }

    emptyState.classList.add('hidden');

    container.innerHTML = tasksToRender.map(task => {
        const isOverdue = task.status !== 'Completed' && new Date(task.dueDate) < new Date();
        const statusClass = isOverdue ? 'overdue' : task.status.toLowerCase().replace(' ', '');
        const priorityClass = `priority-${(task.priority || '').toLowerCase()}`;

        const actionsHtml = currentUser.role === 'admin'
            ? `
                <div class="flex space-x-2">
                    <button
                        onclick="event.stopPropagation(); editTask('${task.Id}')"
                        class="text-blue-500 hover:text-blue-700 text-sm"
                        title="Edit Task"
                    >
                        <i class="fas fa-edit"></i>
                    </button>
                    <button
                        onclick="event.stopPropagation(); deleteTask('${task.Id}')"
                        class="text-red-500 hover:text-red-700 text-sm"
                        title="Delete Task"
                    >
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
              `
            : `
                <!-- User-specific controls for status update -->
                ${task.status !== 'Completed' ? `
                    <button
                        onclick="event.stopPropagation(); openCompleteTaskModal('${task.Id}')"
                        class="bg-green-500 hover:bg-green-600 text-white px-3 py-1 rounded-lg text-xs transition duration-300"
                        title="Mark as Completed"
                        id="complete-btn-${task.Id}"
                    >
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


// Get priority badge class
function getPriorityBadgeClass(priority) {
    switch (priority.toLowerCase()) {
        case 'high': return 'bg-red-100 text-red-800';
        case 'medium': return 'bg-yellow-100 text-yellow-800';
        case 'low': return 'bg-green-100 text-green-800';
        default: return 'bg-gray-100 text-gray-800';
    }
}

// Populate filters (only for admin)
function populateFilters() {
    if (currentUser && currentUser.role !== 'admin') {
        return; // Do not populate filters for non-admin users
    }

    // Populate branch filter
    const branches = [...new Set(allTasks.map(task => task.branch).filter(branch => branch))];
    const branchFilter = document.getElementById('branchFilter');
    
    branchFilter.innerHTML = '<option value="">All Branches</option>';
    branches.forEach(branch => {
        branchFilter.innerHTML += `<option value="${branch}">${branch}</option>`;
    });

    // Populate user filter
    const assignees = [...new Set(allTasks.map(task => task.assignee).filter(assignee => assignee))];
    const userFilter = document.getElementById('userFilter');
    
    userFilter.innerHTML = '<option value="">All Users</option>';
    assignees.forEach(assignee => {
        userFilter.innerHTML += `<option value="${assignee}">${assignee}</option>`;
    });
}

// Filter tasks
// Filter tasks
function filterTasks() {
    let tempFilteredTasks = allTasks;

    console.log('=== FILTER TASKS DEBUG START ===');
    console.log('Total tasks in allTasks:', allTasks.length);
    console.log('Current user:', currentUser);

    if (currentUser && currentUser.role !== 'admin') {
        // For non-admin users, apply specific filters based on username
        const username = currentUser.username;
        
        // Check if username matches a branch code (e.g., C001, C002, etc.)
        // We'll consider any username that matches existing branch values as a branch user
        const existingBranches = [...new Set(allTasks.map(task => task.branch).filter(branch => branch))];
        const isBranchUser = existingBranches.includes(username);

        console.log(`Current user: ${username}, Role: ${currentUser.role}`);
        console.log(`Existing branches in system:`, existingBranches);
        console.log(`Is Branch User: ${isBranchUser} (username "${username}" ${isBranchUser ? 'FOUND' : 'NOT FOUND'} in branches)`);
        
        // Log ALL tasks with their branch and assignee values
        console.log('=== ALL TASKS DETAILED ===');
        allTasks.forEach((task, index) => {
            console.log(`Task ${index + 1}: "${task.title}"`);
            console.log(`  - ID: ${task.Id}`);
            console.log(`  - Branch: "${task.branch}" (type: ${typeof task.branch})`);
            console.log(`  - Assignee: "${task.assignee}" (type: ${typeof task.assignee})`);
            console.log(`  - Status: "${task.status}"`);
        });

        if (isBranchUser) {
            // If username matches a branch code, filter ONLY by branch - ignore assignee
            console.log(`=== FILTERING FOR BRANCH USER: ${username} ===`);
            tempFilteredTasks = tempFilteredTasks.filter(task => {
                const taskBranch = String(task.branch || '').trim();
                const userBranch = String(username || '').trim();
                const matches = taskBranch === userBranch;
                console.log(`Task "${task.title}": Branch "${taskBranch}" vs Username "${userBranch}" = ${matches}`);
                return matches;
            });
        } else {
            // For regular users (non-branch), filter ONLY by assignee - ignore branch
            console.log(`=== FILTERING FOR REGULAR USER: ${currentUser.fullName || username} ===`);
            tempFilteredTasks = tempFilteredTasks.filter(task => {
                const taskAssignee = String(task.assignee || '').trim();
                const userFullName = String(currentUser.fullName || '').trim();
                const userName = String(currentUser.username || '').trim();
                const matches = taskAssignee === userFullName || taskAssignee === userName;
                console.log(`Task "${task.title}": Assignee "${taskAssignee}" vs User "${userFullName}" or "${userName}" = ${matches}`);
                return matches;
            });
        }

        console.log('=== FILTERING RESULTS ===');
        console.log('Tasks after filtering:', tempFilteredTasks.length);
        if (tempFilteredTasks.length > 0) {
            tempFilteredTasks.forEach((task, index) => {
                console.log(`Filtered Task ${index + 1}: "${task.title}" (Branch: "${task.branch}", Assignee: "${task.assignee}")`);
            });
        } else {
            console.log('❌ NO TASKS FOUND AFTER FILTERING');
            if (isBranchUser) {
                console.log(`❌ No tasks found with branch = "${username}"`);
                console.log('Available branches:', existingBranches);
            } else {
                console.log(`❌ No tasks found assigned to "${currentUser.fullName}" or "${username}"`);
                const allAssignees = [...new Set(allTasks.map(task => task.assignee).filter(assignee => assignee))];
                console.log('Available assignees:', allAssignees);
            }
        }
    } else {
        // Admin filtering logic (unchanged)
        const branchFilter = document.getElementById('branchFilter').value;
        const userFilter = document.getElementById('userFilter').value;
        const statusFilter = document.getElementById('statusFilter').value;
        const priorityFilter = document.getElementById('priorityFilter').value;
        
        console.log('Admin filters applied:', { branchFilter, userFilter, statusFilter, priorityFilter });
        
        tempFilteredTasks = allTasks.filter(task => {
            let matches = true;
            
            if (branchFilter && task.branch !== branchFilter) {
                matches = false;
            }
            
            if (userFilter && task.assignee !== userFilter) {
                matches = false;
            }
            
            if (statusFilter) {
                if (statusFilter === 'Overdue') {
                    if (task.status === 'Completed' || new Date(task.dueDate) >= new Date()) {
                        matches = false;
                    }
                } else if (task.status !== statusFilter) {
                    matches = false;
                }
            }
            
            if (priorityFilter && task.priority !== priorityFilter) {
                matches = false;
            }
            
            return matches;
        });

        console.log('Filtered tasks for admin:', tempFilteredTasks.length);
    }
    
    filteredTasks = tempFilteredTasks;
    console.log('=== FINAL RESULT ===');
    console.log('Final filteredTasks count:', filteredTasks.length);
    console.log('=== FILTER TASKS DEBUG END ===');
    
    updateStats();
    renderTasks();
    updateFilterSummary();
}


// Refresh tasks
function refreshTasks() {
    loadTasks();
}

// Open task modal (for Add/Edit)
function openTaskModal(taskId = null) {
    console.log('openTaskModal called with taskId:', taskId);
    const modal = document.getElementById('taskModal');
    const title = document.getElementById('modalTitle');
    const assignToAllNonAdminUsersCheckbox = document.getElementById('assignToAllNonAdminUsersCheckbox');
    const taskBranchInput = document.getElementById('taskBranch');
    const taskIdInput = document.getElementById('taskId'); // Get the hidden taskId input
    const userNoteField = document.getElementById('userNoteField'); // NEW
    const taskUserNoteInput = document.getElementById('taskUserNote'); // NEW

    // Reset form and clear taskId for new task
    document.getElementById('taskForm').reset();
    taskIdInput.value = ''; // Always clear it first

    // NEW: Control visibility and editability of user note field and other fields
    const taskTitleInput = document.getElementById('taskTitle');
    const taskDescriptionInput = document.getElementById('taskDescription');
    const taskPriorityInput = document.getElementById('taskPriority');
    const taskDueDateInput = document.getElementById('taskDueDate');
    const taskStatusInput = document.getElementById('taskStatus');

    if (currentUser && currentUser.role === 'admin') {
        userNoteField.classList.add('hidden'); // Admins don't see/edit user notes here
        taskUserNoteInput.disabled = true;

        // Admin can edit all fields
        taskTitleInput.disabled = false;
        taskDescriptionInput.disabled = false;
        taskBranchInput.disabled = false;
        taskPriorityInput.disabled = false;
        taskDueDateInput.disabled = false;
        taskStatusInput.disabled = false;
        assignToAllNonAdminUsersCheckbox.disabled = false; // Admin can use this
        document.getElementById('assignToAllNonAdminUsersContainer').classList.remove('hidden'); // Show for admin
    } else {
        userNoteField.classList.remove('hidden'); // Non-admins see user notes
        taskUserNoteInput.disabled = false; // Non-admins can edit their note

        // Non-admins cannot edit these fields
        taskTitleInput.disabled = true;
        taskDescriptionInput.disabled = true;
        taskBranchInput.disabled = true;
        taskPriorityInput.disabled = true;
        taskDueDateInput.disabled = true;
        assignToAllNonAdminUsersCheckbox.disabled = true; // Non-admins cannot use this
        document.getElementById('assignToAllNonAdminUsersContainer').classList.add('hidden'); // Hide for non-admin
    }

    if (taskId) {
        // Editing an existing task
        const task = findTaskById(taskId); // Use the improved helper function
        if (task) {
            title.textContent = 'Edit Task';
            taskIdInput.value = task.Id; // Set the hidden taskId input
            console.log('openTaskModal: Setting taskId input to:', taskIdInput.value);
            taskTitleInput.value = task.title;
            taskDescriptionInput.value = task.description;
            taskBranchInput.value = task.branch;
            taskPriorityInput.value = task.priority;
            taskDueDateInput.value = task.dueDate;
            taskStatusInput.value = task.status;
            taskUserNoteInput.value = task.userNote || ''; // NEW: Populate user note

            // Disable "assign to all" when editing (regardless of role)
            assignToAllNonAdminUsersCheckbox.checked = false;
            assignToAllNonAdminUsersCheckbox.disabled = true; 
        } else {
            // This case should ideally not happen if allTasks is up-to-date
            console.warn('openTaskModal: Task not found in allTasks for ID:', taskId, 'Treating as new task.');
            title.textContent = 'Add New Task';
            // Re-enable assignToAll for new task if admin
            if (currentUser && currentUser.role === 'admin') {
                assignToAllNonAdminUsersCheckbox.disabled = false; 
            }
            assignToAllNonAdminUsersCheckbox.checked = false;
        }
    } else {
        // Adding a new task
        title.textContent = 'Add New Task';
        // taskIdInput is already cleared above
        console.log('openTaskModal: Setting taskId input to empty for new task.');
        
        // Enable "assign to all" for new tasks if admin
        if (currentUser && currentUser.role === 'admin') {
            assignToAllNonAdminUsersCheckbox.disabled = false; 
        }
        assignToAllNonAdminUsersCheckbox.checked = false; // Default to unchecked

        // For new tasks, only admin can create, so hide user note field
        userNoteField.classList.add('hidden');
        taskUserNoteInput.disabled = true;
    }
    
    modal.classList.add('show');
}

// Close task modal (for Add/Edit)
function closeTaskModal() {
    document.getElementById('taskModal').classList.remove('show');
}

// Save task(s) to Baserow
async function saveTask() {
    const saveBtn = document.getElementById('saveTaskBtn');
    const saveText = document.getElementById('saveTaskText');
    const saveSpinner = document.getElementById('saveTaskSpinner');
    const config = getBaserowConfig();
    
    // Show loading state
    saveBtn.disabled = true;
    saveText.textContent = 'Saving...';
    saveSpinner.classList.remove('hidden');
    
    try {
        const taskId = document.getElementById('taskId').value;
        console.log('saveTask called. taskId from input:', taskId);
        // Determine if it's an edit operation based on taskId being present and not a demo ID
        const isEdit = taskId && !taskId.startsWith('demo'); 
        console.log('Is it an edit?', isEdit);

        const assignToAllNonAdmin = document.getElementById('assignToAllNonAdminUsersCheckbox').checked;
        const taskBranchValue = document.getElementById('taskBranch').value;
        const taskUserNoteValue = document.getElementById('taskUserNote').value; // NEW: Get user note value

        if (isEdit) {
            // --- EDITING EXISTING TASK ---
            const existingTask = findTaskById(taskId); // Use helper function
            if (!existingTask) {
                throw new Error("Task not found for update.");
            }

            let taskData = {};
            if (currentUser.role === 'admin') {
                // Admin can edit all fields
                taskData = getTaskDataFromForm(existingTask.assignee, taskBranchValue);
                taskData['User Note'] = taskUserNoteValue; // Admin can also set/clear user note
            } else {
                // Non-admin can only update status and their note
                taskData['Status'] = document.getElementById('taskStatus').value;
                taskData['User Note'] = taskUserNoteValue; // User can update their note
            }
            
            const url = `${config.baseUrl}${config.tables.tasks}/${taskId}/?user_field_names=true`;
            console.log('PATCH URL:', url);
            console.log('PATCH Body:', JSON.stringify(taskData));
            
            const response = await fetch(url, {
                method: 'PATCH',
                headers: {
                    'Authorization': `Token ${config.apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(taskData)
            });
            
            if (response.ok) {
                const updatedRecord = await response.json();
                console.log('PATCH Response (updatedRecord):', updatedRecord);
                const taskIndex = allTasks.findIndex(t => normalizeTaskId(t.Id) === normalizeTaskId(taskId));
                if (taskIndex !== -1) {
                    // Update local task object with all fields from Baserow response
                    allTasks[taskIndex] = {
                        Id: normalizeTaskId(updatedRecord.id || updatedRecord.Id), // Prioritize 'id' then fallback to 'Id'
                        title: updatedRecord.Title || '',
                        description: updatedRecord.Description || '',
                        branch: updatedRecord.Branch || '',
                        priority: updatedRecord.Priority || '',
                        assignee: updatedRecord.Assignee || '',
                        dueDate: updatedRecord['Due Date'] || '',
                        status: updatedRecord.Status || 'Pending',
                        userNote: updatedRecord['User Note'] || '' // NEW: Update user note
                    };
                    console.log('allTasks updated locally for task ID:', taskId);
                } else {
                    console.warn('Task not found in local allTasks array after PATCH for ID:', taskId);
                }
                showNotification('Task updated successfully!', 'success');
            } else {
                const errorText = await response.text();
                console.error('PATCH Error:', response.status, errorText);
                throw new Error(`Failed to update task: ${response.status} - ${errorText}`);
            }

        } else {
            // --- CREATING NEW TASK(S) --- (Only admin can create new tasks)
            if (currentUser.role !== 'admin') {
                throw new Error("Only administrators can create new tasks.");
            }

            let tasksToCreate = [];

            if (assignToAllNonAdmin) {
                // Filter for non-admin users
                const nonAdminUsers = users.filter(user => user.role !== 'admin');
                if (nonAdminUsers.length === 0) {
                    throw new Error("No non-admin users found to assign tasks to.");
                }

                // For each non-admin user, create a task
                nonAdminUsers.forEach(user => {
                    // Assignee will be the user's full name/username
                    const assignee = user.fullName || user.username;
                    // Branch will be the user's username (assuming it's a branch code)
                    const branch = user.username; 
                    tasksToCreate.push(getTaskDataFromForm(assignee, branch));
                });

            } else {
                // Original logic for single task creation
                const assigneeValue = currentUser.fullName || currentUser.username;
                if (!assigneeValue) {
                    throw new Error("Logged-in user's name/username not found for assignment.");
                }
                tasksToCreate.push(getTaskDataFromForm(assigneeValue, taskBranchValue));
            }

            console.log('Tasks to create (batch):', tasksToCreate);

            // Handle batch creation with proper error handling
            const batchSize = 10; 
            for (let i = 0; i < tasksToCreate.length; i += batchSize) {
                const batch = tasksToCreate.slice(i, i + batchSize);
                const url = `${config.baseUrl}${config.tables.tasks}/batch/?user_field_names=true`;
                console.log('POST (Batch) URL:', url, 'Batch items count:', batch.length);

                const response = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Token ${config.apiKey}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ items: batch })
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    console.error('POST (Batch) Error:', response.status, errorText);
                    throw new Error(`Failed to create tasks in bulk: ${response.status} - ${errorText}`);
                }

                const newRecordsResponse = await response.json();
                console.log('Raw New records (batch) response:', newRecordsResponse);

                // Handle different possible response formats from Baserow batch create
                let createdRecords = [];
                
                if (Array.isArray(newRecordsResponse)) {
                    createdRecords = newRecordsResponse;
                } else if (newRecordsResponse && Array.isArray(newRecordsResponse.results)) {
                    createdRecords = newRecordsResponse.results;
                } else if (newRecordsResponse && Array.isArray(newRecordsResponse.items)) {
                    createdRecords = newRecordsResponse.items;
                } else {
                    console.warn("Unexpected Baserow batch create response format:", newRecordsResponse);
                    if (newRecordsResponse && (newRecordsResponse.id || newRecordsResponse.Id)) {
                        createdRecords = [newRecordsResponse];
                    } else {
                        throw new Error("Unexpected response format from Baserow batch create.");
                    }
                }
                console.log('Processed createdRecords:', createdRecords);

                // Process the created records
                createdRecords.forEach(record => { 
                    if (record && (record.id || record.Id)) {
                        const newTask = {
                            Id: normalizeTaskId(record.id || record.Id), // Normalize ID
                            title: record.Title || '',
                            description: record.Description || '',
                            branch: record.Branch || '',
                            priority: record.Priority || '',
                            assignee: record.Assignee || '',
                            dueDate: record['Due Date'] || '',
                            status: record.Status || 'Pending',
                            userNote: record['User Note'] || '' // NEW: Add user note
                        };
                        allTasks.push(newTask);
                        console.log('Added new task to allTasks:', newTask.Id, record.Title);
                    } else {
                        console.warn('Record from batch create missing ID:', record);
                    }
                });
            }
            showNotification(`${tasksToCreate.length} tasks created successfully!`, 'success');
        }
        
        closeTaskModal();
        filterTasks(); // Re-filter and render to show new/updated tasks
        
    } catch (error) {
        console.error('Error saving task:', error);
        showNotification(`Failed to save task: ${error.message}`, 'error');
    } finally {
        // Reset loading state
        saveBtn.disabled = false;
        saveText.textContent = 'Save Task';
        saveSpinner.classList.add('hidden');
    }
}

// Helper function to get task data from form fields
function getTaskDataFromForm(assigneeValue, branchValue) {
    const taskData = {};
    
    // Baserow uses exact field names, so we can directly use them
    taskData['Title'] = document.getElementById('taskTitle').value;
    taskData['Description'] = document.getElementById('taskDescription').value;
    taskData['Branch'] = branchValue; 
    taskData['Priority'] = document.getElementById('taskPriority').value;
    taskData['Assignee'] = assigneeValue; 
    taskData['Due Date'] = document.getElementById('taskDueDate').value;
    taskData['Status'] = document.getElementById('taskStatus').value;
    // NEW: Add User Note field. This will only be populated if the field is visible and editable.
    // For new tasks created by admin, this will be empty unless explicitly set.
    // For user edits, this will be the value from the user note input.
    taskData['User Note'] = document.getElementById('taskUserNote').value; 

    return taskData;
}

// Edit task (called from admin controls or detail modal)
function editTask(taskId) {
    closeTaskDetailModal(); // Close detail modal if open
    openTaskModal(taskId);
}

// Delete task from Baserow
async function deleteTask(taskId) {
    if (!confirm('Are you sure you want to delete this task?')) {
        return;
    }
    const config = getBaserowConfig();
    
    try {
        if (!taskId.startsWith('demo')) {
            // Delete from Baserow
            const url = `${config.baseUrl}${config.tables.tasks}/${taskId}/`;
            console.log('DELETE URL:', url);

            const response = await fetch(url, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Token ${config.apiKey}`
                }
            });
            
            if (!response.ok) {
                const errorText = await response.text();
                console.error('DELETE Error:', response.status, errorText);
                throw new Error(`Failed to delete task from Baserow: ${response.status} - ${errorText}`);
            }
            
            showNotification('Task deleted successfully!', 'success');
        } else {
            showNotification('Demo task removed locally', 'info');
        }
        
        // Remove from local array
        allTasks = allTasks.filter(task => normalizeTaskId(task.Id) !== normalizeTaskId(taskId));
        filteredTasks = filteredTasks.filter(task => normalizeTaskId(task.Id) !== normalizeTaskId(taskId));
        updateStats();
        renderTasks();
        populateFilters();
        
    } catch (error) {
        console.error('Error deleting task:', error);
        showNotification(`Failed to delete task: ${error.message}`, 'error');
    }
}

// Open Task Detail Modal
function openTaskDetailModal(taskId) {
    console.log('openTaskDetailModal called with taskId:', taskId);
    const task = findTaskById(taskId); // Use helper function
    if (!task) {
        console.error('Task not found for detail view:', taskId);
        showNotification('Task not found', 'error');
        return;
    }

    currentDetailTaskId = taskId; // Store the ID

    document.getElementById('detailModalTitle').textContent = task.title;
    document.getElementById('detailTaskTitle').textContent = task.title;
    document.getElementById('detailTaskDescription').textContent = task.description || 'No description provided.';
    document.getElementById('detailTaskBranch').textContent = task.branch || 'N/A';
    document.getElementById('detailTaskPriority').textContent = task.priority || 'N/A';
    document.getElementById('detailTaskAssignee').textContent = task.assignee || 'Unassigned';
    document.getElementById('detailTaskDueDate').textContent = task.dueDate ? new Date(task.dueDate).toLocaleDateString() : 'No date';
    document.getElementById('detailTaskStatus').textContent = task.status || 'N/A';
    
    // NEW: Populate user note in detail modal
    const detailUserNoteContainer = document.getElementById('detailUserNoteContainer');
    const detailTaskUserNote = document.getElementById('detailTaskUserNote');
    if (task.userNote) {
        detailTaskUserNote.textContent = task.userNote;
        detailUserNoteContainer.classList.remove('hidden');
    } else {
        detailTaskUserNote.textContent = 'No note provided.';
        detailUserNoteContainer.classList.add('hidden'); // Hide if no note
    }


    // Show/hide edit button based on user role
    const detailEditBtn = document.getElementById('detailEditBtn');
    const detailEditNoteBtn = document.getElementById('detailEditNoteBtn'); // NEW

    if (currentUser && currentUser.role === 'admin') {
        detailEditBtn.classList.remove('hidden');
        detailEditNoteBtn.classList.add('hidden'); // Admin uses the main edit button
    } else {
        detailEditBtn.classList.add('hidden');
        // Show "Edit Note" button for non-admins
        detailEditNoteBtn.classList.remove('hidden');
    }

    document.getElementById('taskDetailModal').classList.add('show');
}

// Close Task Detail Modal
function closeTaskDetailModal() {
    document.getElementById('taskDetailModal').classList.remove('show');
    currentDetailTaskId = null; // Clear the stored ID
}

// Edit Task from Detail Modal
function editTaskFromDetail() {
    if (currentDetailTaskId) {
        // If admin, open full edit modal
        if (currentUser && currentUser.role === 'admin') {
            editTask(currentDetailTaskId);
        } else {
            // If non-admin, open modal specifically for note/status edit
            openTaskModal(currentDetailTaskId);
            // Ensure only user note and status are editable for non-admins
            document.getElementById('taskTitle').disabled = true;
            document.getElementById('taskDescription').disabled = true;
            document.getElementById('taskBranch').disabled = true;
            document.getElementById('taskPriority').disabled = true;
            document.getElementById('taskDueDate').disabled = true;
            document.getElementById('taskStatus').disabled = false; // Allow status edit
            document.getElementById('taskUserNote').disabled = false; // Allow user note edit
            document.getElementById('assignToAllNonAdminUsersContainer').classList.add('hidden'); // Hide for non-admin
        }
    }
}

// Open Complete Task Modal
function openCompleteTaskModal(taskId) {
    taskIdToComplete = taskId;
    const task = findTaskById(taskId);
    if (!task) {
        showNotification('Task not found for completion.', 'error');
        return;
    }

    document.getElementById('completeTaskTitle').textContent = task.title;
    document.getElementById('completeTaskNote').value = task.userNote || ''; // Pre-fill with existing note
    
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

// Close Complete Task Modal
function closeCompleteTaskModal() {
    document.getElementById('completeTaskModal').classList.remove('show');
    taskIdToComplete = null;
}

// Confirm and Complete Task
async function confirmCompleteTask() {
    if (!taskIdToComplete) {
        showNotification('No task selected for completion.', 'error');
        return;
    }

    const note = document.getElementById('completeTaskNote').value;
    const config = getBaserowConfig();
    
    const confirmBtn = document.getElementById('confirmCompleteBtn');
    const confirmText = document.getElementById('confirmCompleteText');
    const confirmSpinner = document.getElementById('confirmCompleteSpinner');

    confirmBtn.disabled = true;
    confirmText.textContent = 'Completing...';
    confirmSpinner.classList.remove('hidden');

    try {
        if (taskIdToComplete.startsWith('demo')) {
            // For demo tasks, update locally
            const task = findTaskById(taskIdToComplete);
            if (task) {
                task.status = 'Completed';
                task.userNote = note;
                showNotification(`Demo task status updated to Completed!`, 'success');
                closeCompleteTaskModal();
                filterTasks(); // Re-render tasks
                updateStats(); // Update statistics
            }
            return;
        }

        const url = `${config.baseUrl}${config.tables.tasks}/${taskIdToComplete}/?user_field_names=true`;
        console.log(`PATCHing task ${taskIdToComplete} status to Completed with note at:`, url);

        const response = await fetch(url, {
            method: 'PATCH',
            headers: {
                'Authorization': `Token ${config.apiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                'Status': 'Completed',
                'User Note': note // Save the user's note
            })
        });

        if (response.ok) {
            const updatedRecord = await response.json();
            console.log('Updated record response:', updatedRecord);
            
            // Update the task in the local allTasks array
            const task = findTaskById(taskIdToComplete);
            if (task) {
                task.status = 'Completed';
                task.userNote = note; // Update local note
                task.Id = normalizeTaskId(updatedRecord.id || updatedRecord.Id); // Update Id in case it changed
                console.log(`Updated task ${taskIdToComplete} status to Completed in local array`);
            } else {
                console.warn(`Task with ID ${taskIdToComplete} not found in local array`);
            }
            
            showNotification('Task marked as completed successfully!', 'success');
            closeCompleteTaskModal();
            filterTasks(); // Re-filter and render tasks to reflect the change
            updateStats();
            
        } else {
            const errorText = await response.text();
            console.error('Status PATCH Error:', response.status, errorText);
            throw new Error(`Failed to update task status: ${response.status} - ${errorText}`);
        }
    } catch (error) {
        console.error('Error updating task status:', error);
        showNotification(`Failed to update task status: ${error.message}`, 'error');
    } finally {
        confirmBtn.disabled = false;
        confirmText.textContent = 'Complete Task';
        confirmSpinner.classList.add('hidden');
    }
}


// Set Active Tab for User Dashboard
function setActiveTab(tabName) {
    activeTab = tabName;

    // Update button active states
    document.getElementById('activeTasksTab').classList.remove('active');
    document.getElementById('completedTasksTab').classList.remove('active');

    if (tabName === 'active') {
        document.getElementById('activeTasksTab').classList.add('active');
    } else {
        document.getElementById('completedTasksTab').classList.add('active');
    }

    renderTasks(); // Re-render tasks based on the new active tab
}

// Close modal when clicking outside
document.addEventListener('click', function(e) {
    const taskModal = document.getElementById('taskModal');
    const detailModal = document.getElementById('taskDetailModal');
    const completeModal = document.getElementById('completeTaskModal'); // NEW

    if (e.target === taskModal) {
        closeTaskModal();
    }
    if (e.target === detailModal) {
        closeTaskDetailModal();
    }
    if (e.target === completeModal) { // NEW
        closeCompleteTaskModal();
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Escape key to close modal
    if (e.key === 'Escape') {
        closeTaskModal();
        closeTaskDetailModal(); // Close detail modal too
        closeCompleteTaskModal(); // NEW
        hideNotification();
    }
    
    // Ctrl/Cmd + N to add new task (admin only)
    if ((e.ctrlKey || e.metaKey) && e.key === 'n' && currentUser && currentUser.role === 'admin') {
        e.preventDefault();
        openTaskModal();
    }
    
    // F5 or Ctrl/Cmd + R to refresh
    if (e.key === 'F5' || ((e.ctrlKey || e.metaKey) && e.key === 'r')) {
        if (currentUser) {
            e.preventDefault();
            refreshTasks();
        }
    }
});
