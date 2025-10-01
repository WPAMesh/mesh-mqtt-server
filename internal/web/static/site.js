/**
 * Debounce functions for better performance
 * (c) 2018 Chris Ferdinandi, MIT License, https://gomakethings.com
 * @param  {Function} fn The function to debounce
 * https://gomakethings.com/debouncing-your-javascript-events/
 */
var debounce=function(a){var e;return function(){var n=this,i=arguments;e&&window.cancelAnimationFrame(e),e=window.requestAnimationFrame(function(){a.apply(n,i)})}};

/**
 * Main code section
 */

// calculate 40rem in px (based off body font size)
var mqw = parseInt(getComputedStyle(document.body).fontSize) * 40;

// Selection of HTML objects
const burger = document.querySelector('.burger i');
const nav = document.querySelector('#header-nav');

// Defining a function
function toggleNav() {
  burger.classList.toggle('fa-bars');
  burger.classList.toggle('fa-times');
  nav.classList.toggle('nav-active');
}
// Calling the function after click event occurs
burger.addEventListener('click', function() {
  toggleNav();
});

/**
 * Onboarding modal functions
 */

function closeOnboarding() {
  const modal = document.getElementById('onboarding-modal');
  if (modal) {
    modal.classList.remove('opened');
  }
}

function openOnboarding() {
  const modal = document.getElementById('onboarding-modal');
  if (modal) {
    modal.classList.add('opened');
  }
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(function() {
    // Could add a toast notification here
    console.log('Copied to clipboard:', text);
  }).catch(function(err) {
    console.error('Failed to copy:', err);
  });
}

async function setPassword() {
  const password = document.getElementById('mqtt-password').value;
  const confirmPassword = document.getElementById('mqtt-password-confirm').value;
  const messageDiv = document.getElementById('password-message');

  // Clear previous messages
  messageDiv.textContent = '';
  messageDiv.className = 'message';

  // Validation
  if (!password || !confirmPassword) {
    messageDiv.textContent = 'Please fill in both password fields';
    messageDiv.classList.add('error');
    return;
  }

  if (password !== confirmPassword) {
    messageDiv.textContent = 'Passwords do not match';
    messageDiv.classList.add('error');
    return;
  }

  if (password.length < 8) {
    messageDiv.textContent = 'Password must be at least 8 characters';
    messageDiv.classList.add('error');
    return;
  }

  // Send password to server
  try {
    const response = await fetch('/api/set-mqtt-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ password: password })
    });

    const data = await response.json();

    if (data.success) {
      messageDiv.textContent = 'Password set successfully!';
      messageDiv.classList.add('success');

      // Show the other sections
      document.getElementById('password-section').style.display = 'none';
      document.getElementById('credentials-section').style.display = 'block';
      document.getElementById('mqtt-settings-section').style.display = 'block';
      document.getElementById('topic-section').style.display = 'block';
      document.getElementById('lora-settings-section').style.display = 'block';
      document.getElementById('channel-section').style.display = 'block';

      // Store password in session for display (not secure but for convenience)
      document.getElementById('user-password').textContent = password;
    } else {
      messageDiv.textContent = data.message || 'Failed to set password';
      messageDiv.classList.add('error');
    }
  } catch (error) {
    messageDiv.textContent = 'Error connecting to server';
    messageDiv.classList.add('error');
    console.error('Error:', error);
  }
}