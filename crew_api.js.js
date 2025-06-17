// crew-api.js - Add this to your frontend to integrate with your backend

class CrewAPI {
  constructor() {
    this.baseURL = 'http://localhost:5000'; // Change for production
    this.socket = null;
  }

  // Helper method to get JWT token from cookies
  getAuthToken() {
    const cookies = document.cookie.split(';');
    const jwtCookie = cookies.find(cookie => cookie.trim().startsWith('jwt='));
    return jwtCookie ? jwtCookie.split('=')[1] : null;
  }

  // Helper method for authenticated requests
  async authenticatedFetch(url, options = {}) {
    const token = this.getAuthToken();
    if (!token) {
      throw new Error('Not authenticated');
    }

    return fetch(url, {
      ...options,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
        ...options.headers
      }
    });
  }

  // ========== PROJECT ENDPOINTS ==========

  // Get user's projects
  async getMyProjects() {
    const response = await this.authenticatedFetch(`${this.baseURL}/api/projects/my-projects`);
    return response.json();
  }

  // Get chart data for a project
  async getProjectChartData(projectId) {
    const response = await fetch(`${this.baseURL}/api/projects/${projectId}/chart-data`);
    return response.json();
  }

  // ========== APPLICATION ENDPOINTS ==========

  // Apply to a project
  async applyToProject(projectId, applicationData) {
    const response = await this.authenticatedFetch(`${this.baseURL}/api/projects/${projectId}/apply`, {
      method: 'POST',
      body: JSON.stringify(applicationData)
    });
    return response.json();
  }

  // Get applications for a project (creator only)
  async getProjectApplications(projectId) {
    const response = await this.authenticatedFetch(`${this.baseURL}/api/projects/${projectId}/applications`);
    return response.json();
  }

  // Respond to an application (accept/reject)
  async respondToApplication(projectId, applicationId, action, message = '') {
    const response = await this.authenticatedFetch(
      `${this.baseURL}/api/projects/${projectId}/applications/${applicationId}/respond`,
      {
        method: 'POST',
        body: JSON.stringify({ action, message })
      }
    );
    return response.json();
  }

  // Get user's applications
  async getMyApplications() {
    const response = await this.authenticatedFetch(`${this.baseURL}/api/projects/my-applications`);
    return response.json();
  }

  // ========== WALLET ENDPOINTS ==========

  // Generate auth message for Phantom wallet
  async getWalletAuthMessage(publicKey) {
    const response = await this.authenticatedFetch(`${this.baseURL}/api/wallet/auth-message`, {
      method: 'POST',
      body: JSON.stringify({ publicKey })
    });
    return response.json();
  }

  // Connect Phantom wallet
  async connectPhantomWallet(publicKey, signature, timestamp) {
    const response = await this.authenticatedFetch(`${this.baseURL}/api/wallet/connect-phantom`, {
      method: 'POST',
      body: JSON.stringify({ publicKey, signature, timestamp })
    });
    return response.json();
  }

  // Get wallet info
  async getWalletInfo() {
    const response = await this.authenticatedFetch(`${this.baseURL}/api/wallet/info`);
    return response.json();
  }

  // Generate new wallet
  async generateWallet() {
    const response = await this.authenticatedFetch(`${this.baseURL}/api/wallet/generate`, {
      method: 'POST'
    });
    return response.json();
  }

  // ========== CHAT ENDPOINTS ==========

  // Initialize WebSocket connection for real-time chat
  connectToChat() {
    if (this.socket) {
      this.socket.disconnect();
    }

    const token = this.getAuthToken();
    if (!token) {
      throw new Error('Authentication required for chat');
    }

    // Initialize Socket.IO connection
    this.socket = io(this.baseURL, {
      auth: { token },
      transports: ['websocket', 'polling']
    });

    this.socket.on('connect', () => {
      console.log('Connected to chat server');
    });

    this.socket.on('error', (error) => {
      console.error('Chat error:', error);
    });

    return this.socket;
  }

  // Join a project chat room
  joinProjectChat(projectId) {
    if (!this.socket) {
      throw new Error('Chat not connected. Call connectToChat() first.');
    }
    this.socket.emit('join-project', projectId);
  }

  // Send a message to project chat
  sendChatMessage(projectId, content, isTask = false, assigneeXUsername = null) {
    if (!this.socket) {
      throw new Error('Chat not connected. Call connectToChat() first.');
    }
    this.socket.emit('send-message', {
      projectId,
      content,
      isTask,
      assigneeXUsername
    });
  }

  // Get chat messages via REST API (fallback)
  async getChatMessages(projectId, limit = 50, before = null) {
    const params = new URLSearchParams({ limit });
    if (before) params.append('before', before);
    
    const response = await this.authenticatedFetch(
      `${this.baseURL}/api/chat/${projectId}/messages?${params}`
    );
    return response.json();
  }

  // ========== USER/AUTH ENDPOINTS ==========

  // Get user profile
  async getUserProfile() {
    const response = await this.authenticatedFetch(`${this.baseURL}/api/user/profile`);
    return response.json();
  }

  // Logout
  async logout() {
    const response = await this.authenticatedFetch(`${this.baseURL}/auth/logout`, {
      method: 'POST'
    });
    return response.json();
  }

  // ========== UTILITY METHODS ==========

  // Seed sample data (development only)
  async seedSampleData() {
    const response = await fetch(`${this.baseURL}/api/projects/seed-sample-data`, {
      method: 'POST'
    });
    return response.json();
  }

  // Health check
  async healthCheck() {
    const response = await fetch(`${this.baseURL}/health`);
    return response.json();
  }
}

// ========== USAGE EXAMPLES ==========

// Example integration for your Top Projects page
async function loadTopProjects() {
  const api = new CrewAPI();
  
  try {
    const projects = await api.getLaunchedProjects('all', 6);
    
    projects.forEach((project, index) => {
      // Update project card
      updateProjectCard(project, index);
      
      // Draw chart if chart data exists
      if (project.tokenChartPoints) {
        const chartData = JSON.parse(project.tokenChartPoints);
        drawChart(`chart${index + 1}`, chartData);
      }
    });
  } catch (error) {
    console.error('Failed to load top projects:', error);
  }
}

// Example integration for your Join page
async function loadAvailableProjects() {
  const api = new CrewAPI();
  
  try {
    const filters = {
      category: document.getElementById('categoryFilter')?.value || 'all',
      stage: document.getElementById('stageFilter')?.value || 'all',
      search: document.getElementById('searchInput')?.value || ''
    };
    
    const projects = await api.getAvailableProjects(filters);
    updateProjectsList(projects);
  } catch (error) {
    console.error('Failed to load available projects:', error);
  }
}

// Example integration for your Dream page
async function createNewProject(formData) {
  const api = new CrewAPI();
  
  try {
    const projectData = {
      name: formData.get('projectTitle'),
      summary: formData.get('projectDescription'),
      category: formData.get('projectCategory'),
      skillsNeeded: getSelectedSkills(), // Your existing function
      timeline: formData.get('timeline'),
      experienceLevel: formData.get('experience'),
      successMetrics: formData.get('projectGoals'),
      additionalInfo: formData.get('additionalInfo')
    };
    
    const result = await api.createProject(projectData);
    
    if (result.project) {
      alert(`Project "${result.project.name}" created successfully!`);
      window.location.href = `/project-dashboard.html?id=${result.project.id}`;
    }
  } catch (error) {
    console.error('Failed to create project:', error);
    alert('Failed to create project. Please try again.');
  }
}

// Example integration for applying to projects
async function applyToProject(projectId, position, experience, message = '') {
  const api = new CrewAPI();
  
  try {
    const result = await api.applyToProject(projectId, {
      position,
      experience,
      message
    });
    
    alert('Application sent successfully!');
    // Update UI to show application was sent
    updateApplicationStatus(projectId, 'applied');
  } catch (error) {
    console.error('Failed to apply to project:', error);
    alert('Failed to send application. Please try again.');
  }
}

// Example integration for Phantom wallet connection
async function connectPhantomWallet() {
  const api = new CrewAPI();
  
  try {
    // Check if Phantom is installed
    if (!window.solana || !window.solana.isPhantom) {
      alert('Phantom wallet not found. Please install Phantom wallet extension.');
      window.open('https://phantom.app/', '_blank');
      return;
    }
    
    // Connect to Phantom
    const response = await window.solana.connect();
    const publicKey = response.publicKey.toString();
    
    // Get auth message from server
    const { message, timestamp } = await api.getWalletAuthMessage(publicKey);
    
    // Sign the message
    const encodedMessage = new TextEncoder().encode(message);
    const signedMessage = await window.solana.signMessage(encodedMessage, 'utf8');
    const signature = bs58.encode(signedMessage.signature);
    
    // Connect wallet on server
    const result = await api.connectPhantomWallet(publicKey, signature, timestamp);
    
    alert('Phantom wallet connected successfully!');
    console.log('Wallet info:', result.wallet);
    
    // Update UI to show connected wallet
    updateWalletUI(result.wallet);
    
  } catch (error) {
    console.error('Failed to connect Phantom wallet:', error);
    alert('Failed to connect wallet. Please try again.');
  }
}

// Example integration for real-time chat
function initializeProjectChat(projectId) {
  const api = new CrewAPI();
  
  try {
    // Connect to chat server
    const socket = api.connectToChat();
    
    // Set up event listeners
    socket.on('message-history', (messages) => {
      displayChatHistory(messages);
    });
    
    socket.on('new-message', (message) => {
      displayNewMessage(message);
    });
    
    socket.on('user-joined', (user) => {
      updateOnlineUsers();
    });
    
    socket.on('user-typing', (data) => {
      showTypingIndicator(data);
    });
    
    // Join the project chat
    api.joinProjectChat(projectId);
    
    // Set up message sending
    document.getElementById('sendBtn')?.addEventListener('click', () => {
      const input = document.getElementById('messageInput');
      if (input.value.trim()) {
        api.sendChatMessage(projectId, input.value.trim());
        input.value = '';
      }
    });
    
  } catch (error) {
    console.error('Failed to initialize chat:', error);
  }
}

// Make CrewAPI available globally
window.CrewAPI = CrewAPI;

// Auto-initialize for development
if (window.location.hostname === 'localhost') {
  window.crewAPI = new CrewAPI();
  console.log('🚀 CREW API initialized for development');
  console.log('Available at: window.crewAPI');
} launched projects for Top Projects page
  async getLaunchedProjects(category = 'all', limit = 10) {
    const params = new URLSearchParams({ category, limit });
    const response = await fetch(`${this.baseURL}/api/projects/launched?${params}`);
    return response.json();
  }

  // Get available projects for Join page
  async getAvailableProjects(filters = {}) {
    const params = new URLSearchParams(filters);
    const response = await fetch(`${this.baseURL}/api/projects/available?${params}`);
    return response.json();
  }

  // Get project categories
  async getCategories() {
    const response = await fetch(`${this.baseURL}/api/projects/categories`);
    return response.json();
  }

  // Create new project (Dream page)
  async createProject(projectData) {
    const response = await this.authenticatedFetch(`${this.baseURL}/api/projects`, {
      method: 'POST',
      body: JSON.stringify(projectData)
    });
    return response.json();
  }

  // Get specific project details
  async getProject(projectId) {
    const response = await fetch(`${this.baseURL}/api/projects/${projectId}`);
    return response.json();
  }

  // Update project (creator only)
  async updateProject(projectId, updates) {
    const response = await this.authenticatedFetch(`${this.baseURL}/api/projects/${projectId}`, {
      method: 'PUT',
      body: JSON.stringify(updates)
    });
    return response.json();
  }

  // Get