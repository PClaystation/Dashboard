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
  openLoginPopup();
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

const dev = true;
window.onload = async () => {
  extractParams();

  if (!dev) {
    await tryRefreshToken();
  }

  const token = localStorage.getItem('token');
  const userId = localStorage.getItem('userId');

  if (token && userId) {
    const email = await fetchUserInfo();
    if (email) {
      setLoggedIn(email);
      // User is logged in, show the app now
      await new Promise(resolve => setTimeout(resolve, 1500)); // Optional delay
      showApp();
    } else {
      setLoggedOut();
      // Wait for login popup event before showing app
    }
  } else {
    setLoggedOut();
    // Wait for login popup event before showing app
  }
};


// Logout button
logoutBtn.onclick = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('userId');
  setLoggedOut();
};

// Tab switching
tabButtons.forEach(button => {
  button.addEventListener('click', () => {
    tabButtons.forEach(btn => btn.classList.remove('active'));
    tabContents.forEach(content => content.classList.remove('active'));

    button.classList.add('active');
    const tab = button.getAttribute('data-tab');
    document.getElementById(tab).classList.add('active');
  });
});

// Delete account
document.getElementById('delete-account-btn').onclick = () => {
  if (confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
    alert('Account deletion feature is not implemented yet.');
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

    const text = await res.text();
    console.log('🟡 Raw response from /me:', text);

    if (!res.ok) throw new Error(`Status ${res.status}: ${text}`);

    const data = JSON.parse(text);
    statusDiv.textContent = `Logged in as: ${data.email}`;
    return data.email;
  } catch (err) {
    console.error('❌ fetchUserInfo failed:', err);
    setLoggedOut();
  }
}

async function tryRefreshToken() {
  try {
    const res = await fetch('https://mpmc.ddns.net:5000/api/auth/refresh_token', {
      method: 'POST',
      credentials: 'include',
    });
    if (!res.ok) throw new Error('Refresh token failed');

    const data = await res.json();
    localStorage.setItem('token', data.accessToken);
    return true;
  } catch (err) {
    console.log('Could not refresh token:', err);
    setLoggedOut();
    return false;
  }
}

function openLoginPopup() {
  const width = 500;
  const height = 650;
  const left = (screen.width / 2) - (width / 2);
  const top = (screen.height / 2) - (height / 2);

  window.open(
    'https://pclaystation.github.io/Login/popup.html',
    'LoginPopup',
    `width=${width},height=${height},top=${top},left=${left}`
  );
}

window.addEventListener('message', async (event) => {
  // Remove or comment out origin check during local testing
  // if (event.origin !== 'https://pclaystation.github.io') return;

  console.log('Received message from:', event.origin, event.data);

  if (event.data.type === 'LOGIN_SUCCESS') {
    console.log('✅ Logged in via popup!', event.data);
    localStorage.setItem('token', event.data.token);
    localStorage.setItem('userId', event.data.userId);
    await fetchUserInfo();
    setLoggedIn(event.data.userId);

    await new Promise(resolve => setTimeout(resolve, 1500));
    showApp();
  }
});


function showApp() {
  console.log("✅ showApp() triggered");
  const loadingScreen = document.getElementById('loading-screen');
  const appContent = document.getElementById('app-content');

  if (!loadingScreen || !appContent) {
    console.error("❌ Missing #loading-screen or #app-content");
    return;
  }

  // Use CSS transition on opacity instead of animation event
  loadingScreen.style.transition = 'opacity 0.8s ease';
  loadingScreen.style.opacity = '0';

  // After transition duration, hide loading and show app content
  setTimeout(() => {
    loadingScreen.style.display = 'none';

    appContent.style.display = 'block';
    // Force reflow for transition
    void appContent.offsetWidth;
    appContent.classList.add('fade-in');

    // Cookie popup logic (keep as before)
    const popup = document.getElementById("cookie-popup");
    const acceptBtn = document.getElementById("cookie-accept");

    if (popup && acceptBtn) {
      if (!localStorage.getItem("cookiesAccepted")) {
        popup.classList.remove("hide");
      }

      acceptBtn.addEventListener("click", () => {
        localStorage.setItem("cookiesAccepted", "true");
        popup.classList.add("hide");
      });
    }
  }, 800); // match your CSS transition duration
}
