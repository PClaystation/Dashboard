const statusDiv = document.getElementById('status');
const logoutBtn = document.getElementById('logout-btn');
const tabButtons = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

function setLoggedIn(email) {
    statusDiv.textContent = `Logged in as: ${email}`;
    logoutBtn.style.display = 'inline-block';
  }
  

function setLoggedOut() {
  statusDiv.textContent = 'Not logged in';
  logoutBtn.style.display = 'none';
  localStorage.removeItem('token');
  localStorage.removeItem('userId');
  const loginURL = `https://pclaystation.github.io/Login/?redirect=${encodeURIComponent(window.location.href)}`;
  window.location.href = loginURL;
}

function extractParams() {
  const params = new URLSearchParams(window.location.search);
  const token = params.get('token');
  const userId = params.get('userId');
  if (token && userId) {
    localStorage.setItem('token', token);
    localStorage.setItem('userId', userId);
    setLoggedIn(userId);
    fetchUserInfo();
    const cleanURL = window.location.origin + window.location.pathname;
    history.replaceState({}, '', cleanURL);
  }
}
window.onload = async () => {
    extractParams();

    await tryRefreshToken();
  
    const token = localStorage.getItem('token');
    const userId = localStorage.getItem('userId');
  
    if (token && userId) {
      const email = await fetchUserInfo();
      if (email) {
        setLoggedIn(email);
      } else {
        setLoggedIn(userId);
      }
    } else {
      //setLoggedOut();
    }
  
    // Minimum 1.5 sec loading screen
    await new Promise(resolve => setTimeout(resolve, 1500));
  
    const loadingScreen = document.getElementById('loading-screen');
    const appContent = document.getElementById('app-content');
  
    // Start fade-out animation
    loadingScreen.classList.add('fade-out');
  
    // Wait for animation to finish (0.8s)
    loadingScreen.addEventListener('animationend', () => {
      loadingScreen.style.display = 'none'; // hide it after fade
      appContent.style.display = 'block';    // show main content
    }, { once: true });
  };
  
  
  
  

// Logout button
logoutBtn.onclick = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('userId');
  const loginURL = `https://pclaystation.github.io/Login/?redirect=${encodeURIComponent(window.location.href)}`;
  window.location.href = loginURL;
};

// Tab switching
tabButtons.forEach(button => {
  button.addEventListener('click', () => {
    // Remove active classes
    tabButtons.forEach(btn => btn.classList.remove('active'));
    tabContents.forEach(content => content.classList.remove('active'));

    // Add active to clicked tab and corresponding content
    button.classList.add('active');
    const tab = button.getAttribute('data-tab');
    document.getElementById(tab).classList.add('active');
  });
});

// Example: Delete account confirmation
document.getElementById('delete-account-btn').onclick = () => {
  if (confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
    alert('Account deletion feature is not implemented yet.');
    // Hook here to call your API or backend to delete account
  }
};



async function fetchUserInfo() {
    const token = localStorage.getItem('token');
    if (!token) {
      console.warn('❌ No token in localStorage');
      return;
    }
  
    try {
      const res = await fetch('https://mpmc.ddns.net:5000/api/auth/me', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        }
      });
  
      const text = await res.text(); // instead of res.json()
      console.log('🟡 Raw response from /me:', text);
  
      if (!res.ok) throw new Error(`Status ${res.status}: ${text}`);
  
      const data = JSON.parse(text);
      statusDiv.textContent = `Logged in as: ${data.email}`;
      return data.email;
    } catch (err) {
      console.error('❌ fetchUserInfo failed:', err);
      //setLoggedOut();
    }
  }
  
  async function tryRefreshToken() {
    try {
      const res = await fetch('https://mpmc.ddns.net:5000/api/auth/refresh_token', {
        method: 'POST',
        credentials: 'include', // important to send cookies
      });
      if (!res.ok) throw new Error('Refresh token failed');
  
      const data = await res.json();
      localStorage.setItem('token', data.accessToken); // store new access token
      return true;
    } catch (err) {
      console.log('Could not refresh token:', err);
      //setLoggedOut(); // or show login screen
      return false;
    }
  }
  