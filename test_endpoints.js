// test-endpoints.js - Run this to test your new endpoints

const fetch = require('node-fetch'); // You may need to install: npm install node-fetch@2

const BASE_URL = 'http://localhost:5000';
let authToken = ''; // You'll need to get this from login

// Test functions
async function testEndpoints() {
  console.log('🧪 Testing CREW Platform API Endpoints\n');
  
  try {
    // Test 1: Get launched projects
    console.log('📊 Testing launched projects endpoint...');
    const launchedResponse = await fetch(`${BASE_URL}/api/projects/launched`);
    const launchedData = await launchedResponse.json();
    console.log('✅ Launched projects:', launchedData.length, 'projects found\n');
    
    // Test 2: Get available projects
    console.log('🔍 Testing available projects endpoint...');
    const availableResponse = await fetch(`${BASE_URL}/api/projects/available`);
    const availableData = await availableResponse.json();
    console.log('✅ Available projects:', availableData.length, 'projects found\n');
    
    // Test 3: Get categories
    console.log('📋 Testing categories endpoint...');
    const categoriesResponse = await fetch(`${BASE_URL}/api/projects/categories`);
    const categoriesData = await categoriesResponse.json();
    console.log('✅ Categories:', categoriesData.map(c => c.name).join(', '), '\n');
    
    // Test 4: Health check
    console.log('💚 Testing health endpoint...');
    const healthResponse = await fetch(`${BASE_URL}/health`);
    const healthData = await healthResponse.json();
    console.log('✅ Server health:', healthData.status, '\n');
    
    // Test 5: Seed sample data (development only)
    if (process.env.NODE_ENV !== 'production') {
      console.log('🌱 Seeding sample data...');
      const seedResponse = await fetch(`${BASE_URL}/api/projects/seed-sample-data`, {
        method: 'POST'
      });
      const seedData = await seedResponse.json();
      console.log('✅ Sample data:', seedData.message, '\n');
    }
    
    console.log('🎉 All endpoint tests completed successfully!');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

// Test with authentication (you'll need a valid JWT token)
async function testAuthEndpoints() {
  if (!authToken) {
    console.log('⚠️  No auth token provided. Skipping authenticated endpoint tests.');
    console.log('   To test authenticated endpoints:');
    console.log('   1. Login via /auth/x');
    console.log('   2. Copy the JWT token from cookies');
    console.log('   3. Set authToken variable above');
    return;
  }
  
  console.log('\n🔐 Testing authenticated endpoints...\n');
  
  try {
    // Test: Create a project
    const projectData = {
      name: 'Test DeFi Project',
      summary: 'A test project for automated testing',
      category: 'defi',
      skillsNeeded: ['Rust Developer', 'Smart Contract Auditor'],
      timeline: '3-6 months',
      experienceLevel: 'intermediate',
      successMetrics: 'Launch on mainnet with 1000+ users',
      additionalInfo: 'This is a test project created by automated testing'
    };
    
    const createResponse = await fetch(`${BASE_URL}/api/projects`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`
      },
      body: JSON.stringify(projectData)
    });
    
    const createData = await createResponse.json();
    console.log('✅ Project created:', createData.project?.name || 'Failed');
    
  } catch (error) {
    console.error('❌ Auth test failed:', error.message);
  }
}

// Frontend integration examples
function generateFrontendExamples() {
  console.log('\n📖 Frontend Integration Examples:\n');
  
  console.log('// 1. Get top projects for your Top Projects page');
  console.log(`fetch('${BASE_URL}/api/projects/launched')
  .then(res => res.json())
  .then(projects => {
    // Update your charts with projects[i].tokenChartPoints
    projects.forEach(project => {
      const chartData = JSON.parse(project.tokenChartPoints);
      drawChart(\`chart-\${project._id}\`, chartData);
    });
  });\n`);
  
  console.log('// 2. Get available projects for your Join page');
  console.log(`fetch('${BASE_URL}/api/projects/available?category=defi&stage=mvp')
  .then(res => res.json())
  .then(projects => {
    // Populate your project cards
    updateProjectCards(projects);
  });\n`);
  
  console.log('// 3. Create a new project from your Dream page');
  console.log(`fetch('${BASE_URL}/api/projects', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + getCookie('jwt')
  },
  body: JSON.stringify({
    name: 'My DeFi Project',
    summary: 'Revolutionary DeFi protocol',
    category: 'defi',
    skillsNeeded: ['Rust Developer', 'UI/UX Designer'],
    timeline: '6-12 months',
    experienceLevel: 'advanced'
  })
})
.then(res => res.json())
.then(data => {
  console.log('Project created:', data.project);
  // Redirect to project dashboard
  window.location.href = '/project-dashboard.html?id=' + data.project.id;
});\n`);
  
  console.log('// 4. Apply to a project from your Join page');
  console.log(`fetch('${BASE_URL}/api/projects/PROJECT_ID/apply', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + getCookie('jwt')
  },
  body: JSON.stringify({
    position: 'Frontend Developer',
    experience: '3 years React experience, worked on 2 DeFi projects',
    message: 'Excited to contribute to this innovative project!'
  })
})
.then(res => res.json())
.then(data => {
  alert('Application sent successfully!');
});\n`);
}

// Run tests
if (require.main === module) {
  testEndpoints()
    .then(() => testAuthEndpoints())
    .then(() => generateFrontendExamples());
}

module.exports = { testEndpoints, testAuthEndpoints };