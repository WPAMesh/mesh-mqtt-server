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

let currentWizardStep = 1;
const totalWizardSteps = 6;

function closeOnboarding() {
  const modal = document.getElementById('onboarding-modal');
  if (modal) {
    modal.classList.remove('opened');
  }
}

function openOnboarding(startStep) {
  const modal = document.getElementById('onboarding-modal');
  if (modal) {
    // If opening from setup guide (not first time), start at step 2 and hide step 1
    if (startStep === 2) {
      currentWizardStep = 2;
      // Hide the password step from the progress indicator
      const step1 = document.querySelector('.wizard-step[data-step="1"]');
      if (step1) {
        step1.style.display = 'none';
      }
    } else {
      // First time setup - show all steps starting from step 1
      currentWizardStep = 1;
      const step1 = document.querySelector('.wizard-step[data-step="1"]');
      if (step1) {
        step1.style.display = 'flex';
      }
    }

    updateWizardUI();
    modal.classList.add('opened');
  }
}

function updateWizardUI() {
  // Check if step 1 is hidden (opened from setup guide)
  const step1 = document.querySelector('.wizard-step[data-step="1"]');
  const isStep1Hidden = step1 && step1.style.display === 'none';
  const minStep = isStep1Hidden ? 2 : 1;

  // Update step indicators
  document.querySelectorAll('.wizard-step').forEach(step => {
    const stepNum = parseInt(step.getAttribute('data-step'));
    if (stepNum === currentWizardStep) {
      step.classList.add('active');
      step.classList.remove('completed');
    } else if (stepNum < currentWizardStep) {
      step.classList.add('completed');
      step.classList.remove('active');
    } else {
      step.classList.remove('active', 'completed');
    }
  });

  // Update step content visibility
  document.querySelectorAll('.wizard-step-content').forEach(content => {
    const stepNum = parseInt(content.getAttribute('data-step'));
    content.style.display = stepNum === currentWizardStep ? 'block' : 'none';
    if (stepNum === currentWizardStep) {
      content.classList.add('active');
    } else {
      content.classList.remove('active');
    }
  });

  // Update progress bar (adjust for hidden step 1)
  const progressFill = document.getElementById('wizard-progress-fill');
  if (progressFill) {
    const adjustedSteps = isStep1Hidden ? totalWizardSteps - 1 : totalWizardSteps;
    const adjustedCurrent = isStep1Hidden ? currentWizardStep - 1 : currentWizardStep;
    const progress = ((adjustedCurrent - 1) / (adjustedSteps - 1)) * 100;
    progressFill.style.width = progress + '%';
  }

  // Update navigation buttons
  const prevBtn = document.querySelector('.wizard-btn-prev');
  const nextBtn = document.querySelector('.wizard-btn-next');
  const finishBtn = document.querySelector('.wizard-btn-finish');

  if (prevBtn) {
    prevBtn.style.visibility = currentWizardStep === minStep ? 'hidden' : 'visible';
  }

  if (nextBtn && finishBtn) {
    if (currentWizardStep === totalWizardSteps) {
      nextBtn.style.display = 'none';
      finishBtn.style.display = 'block';
    } else {
      nextBtn.style.display = 'block';
      finishBtn.style.display = 'none';
    }
  }
}

function wizardNextStep() {
  // Special handling for step 1 (password setup)
  if (currentWizardStep === 1) {
    const password = document.getElementById('mqtt-password').value;
    const confirmPassword = document.getElementById('mqtt-password-confirm').value;

    if (!password || !confirmPassword) {
      showPasswordMessage('Please fill in both password fields', 'error');
      return;
    }

    if (password !== confirmPassword) {
      showPasswordMessage('Passwords do not match', 'error');
      return;
    }

    if (password.length < 8) {
      showPasswordMessage('Password must be at least 8 characters', 'error');
      return;
    }

    // Set the password via API
    setPassword();
    return; // setPassword will handle moving to next step
  }

  // Move to next step for all other steps
  if (currentWizardStep < totalWizardSteps) {
    currentWizardStep++;
    updateWizardUI();
  }
}

function wizardPrevStep() {
  if (currentWizardStep > 1) {
    currentWizardStep--;
    updateWizardUI();
  }
}

function showPasswordMessage(message, type) {
  const messageDiv = document.getElementById('password-message');
  if (messageDiv) {
    messageDiv.textContent = message;
    messageDiv.className = 'message ' + type;
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

function updateTopicSelection(role) {
  const topicDisplay = document.getElementById('selected-topic');
  if (topicDisplay && window.mqttTopics) {
    topicDisplay.textContent = window.mqttTopics[role] || window.mqttTopics.standard;
  }
}

function copySelectedTopic() {
  const topicDisplay = document.getElementById('selected-topic');
  if (topicDisplay) {
    copyToClipboard(topicDisplay.textContent);
  }
}

/**
 * Validation errors modal functions
 */
function showValidationErrors(element) {
  const nodeId = element.getAttribute('data-node-id');
  const nodeName = element.getAttribute('data-node-name');
  const isValid = element.getAttribute('data-is-valid') === 'true';

  // Get validation errors from stored data
  const errors = nodeValidationErrors[nodeId] || [];

  const modal = document.getElementById('validation-modal');
  const title = document.getElementById('validation-modal-title');
  const body = document.getElementById('validation-modal-body');

  if (!modal || !title || !body) {
    console.error('Validation modal elements not found');
    return;
  }

  // Update modal title
  title.textContent = `Gateway Validation - ${nodeName || nodeId}`;

  // Populate errors
  if (isValid || errors.length === 0) {
    body.innerHTML = '<p class="validation-success"><i class="fas fa-check-circle"></i> No validation errors - this node is a valid gateway!</p>';
  } else {
    body.innerHTML = '<ul class="validation-errors-list">' +
      errors.map(error => `<li><i class="fas fa-exclamation-circle"></i> ${error}</li>`).join('') +
      '</ul>';
  }

  // Show modal
  modal.classList.add('opened');
}

function closeValidationModal() {
  const modal = document.getElementById('validation-modal');
  if (modal) {
    modal.classList.remove('opened');
  }
}

async function setPassword() {
  const password = document.getElementById('mqtt-password').value;
  const messageDiv = document.getElementById('password-message');

  // Clear previous messages
  messageDiv.textContent = '';
  messageDiv.className = 'message';

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
      showPasswordMessage('Password set successfully!', 'success');

      // Store password in session for display (not secure but for convenience)
      //document.getElementById('user-password').textContent = password;

      // Move to next step in wizard after a brief delay
      setTimeout(() => {
        currentWizardStep++;
        updateWizardUI();
      }, 500);
    } else {
      showPasswordMessage(data.message || 'Failed to set password', 'error');
    }
  } catch (error) {
    showPasswordMessage('Error connecting to server', 'error');
    console.error('Error:', error);
  }
}

/**
 * Node table management
 */

let autoRefreshTimeout = null;
let isLoadingNodes = false;
let nodeValidationErrors = {}; // Store validation errors by node ID

function getFilters() {
  const connectedCheckbox = document.getElementById('filter-connected');
  // For hidden inputs, check the 'checked' attribute exists, otherwise use .checked
  const connectedOnly = connectedCheckbox ?
    (connectedCheckbox.type === 'hidden' ? connectedCheckbox.hasAttribute('checked') : connectedCheckbox.checked) :
    false;
  const gatewayOnly = document.getElementById('filter-gateway')?.checked || false;

  return { connectedOnly, gatewayOnly };
}

async function loadNodes(isAdmin = false) {
  // Prevent concurrent requests
  if (isLoadingNodes) {
    return;
  }

  isLoadingNodes = true;

  try {
    const filters = getFilters();
    const params = new URLSearchParams();

    if (filters.connectedOnly) params.append('connected_only', 'true');
    if (filters.gatewayOnly) params.append('valid_gateway_only', 'true');
    if (isAdmin) params.append('all_users', 'true');

    const response = await fetch(`/api/nodes?${params.toString()}`);

    if (!response.ok) {
      throw new Error('Failed to fetch nodes');
    }

    const data = await response.json();

    // Check if we have a table or grid layout
    const hasTable = document.getElementById('nodes-tbody') !== null;
    const hasGrid = document.getElementById('node-grid') !== null;

    if (hasTable) {
      renderNodesTable(data.nodes, isAdmin);
    } else if (hasGrid) {
      renderNodeCards(data.nodes);
    }

    renderOtherClientsTable(data.other_clients, isAdmin);

  } catch (error) {
    console.error('Error loading nodes:', error);

    // Handle error display for grid or table
    const grid = document.getElementById('node-grid');
    const tbody = document.getElementById('nodes-tbody');

    if (grid) {
      grid.innerHTML = '<div class="error-message">Error loading nodes</div>';
    } else if (tbody) {
      tbody.innerHTML = '<tr><td colspan="' + (isAdmin ? '8' : '7') + '" class="error-message">Error loading nodes</td></tr>';
    }

    const otherTbody = document.getElementById('other-clients-tbody');
    if (otherTbody) {
      otherTbody.innerHTML = '<tr><td colspan="' + (isAdmin ? '3' : '2') + '" class="error-message">Error loading clients</td></tr>';
    }
  } finally {
    isLoadingNodes = false;

    // Schedule next refresh if auto-refresh is enabled (admin only)
    if (isAdmin) {
      const autoRefresh = document.getElementById('auto-refresh')?.checked || false;
      if (autoRefresh) {
        scheduleNextRefresh(isAdmin);
      }
    }
  }
}

function scheduleNextRefresh(isAdmin) {
  // Clear any existing timeout
  if (autoRefreshTimeout) {
    clearTimeout(autoRefreshTimeout);
  }

  // Schedule next refresh in 15 seconds
  autoRefreshTimeout = setTimeout(() => {
    loadNodes(isAdmin);
  }, 15000);
}

function renderNodeCards(nodes) {
  const grid = document.getElementById('node-grid');

  if (!grid) {
    console.error('Node grid element not found');
    return;
  }

  if (!nodes || nodes.length === 0) {
    grid.innerHTML = '<div class="no-nodes-message"><i>No nodes found</i></div>';
    return;
  }

  // Store validation errors for later access
  nodeValidationErrors = {};
  nodes.forEach(node => {
    if (node.node_id && node.validation_errors) {
      nodeValidationErrors[node.node_id] = node.validation_errors;
    }
  });

  // Generate node cards HTML
  grid.innerHTML = nodes.map(node => {
    const nodeColor = node.node_color || '128, 128, 128'; // Default gray
    const shortName = node.short_name || '?';
    const longName = node.long_name || 'unknown';
    const nodeId = node.node_id || 'n/a';
    const nodeRole = node.node_role || 'n/a';
    const rootTopic = node.root_topic || '';
    const address = node.address || '';
    const ipAddress = address ? address.split(':')[0] : 'disconnected';
    const isDownlink = node.is_downlink || false;
    const isValidGateway = node.is_valid_gateway || false;
    const proxyType = node.proxy_type || '';

    // Proxy icon
    let proxyIcon = '';
    if (proxyType === 'Android') {
      proxyIcon = '<i class="fab fa-android" style="font-size: 1.25em; margin-left: 0.5rem;" title="Android Proxy"></i>';
    } else if (proxyType === 'Apple') {
      proxyIcon = '<i class="fab fa-apple" style="font-size: 1.25em; margin-left: 0.5rem;" title="iOS Proxy"></i>';
    }

    return `
      <div class="node-card mg-border mg-rounded1" style="--node-color: rgb(${nodeColor}); --node-color-bg: rgba(${nodeColor}, 0.15);">
        <!-- Header -->
        <div class="node-header">
          <div class="node-header-left">
            <span class="node-badge">${shortName}</span>
            <span class="node-name">${longName}</span>
          </div>
          <div class="mg-row mg-items-center">
            ${proxyIcon}
          </div>
        </div>

        <!-- Root topic -->
        <div class="node-topic">
          Topic: <code>${rootTopic}</code>
        </div>

        <!-- Downlink + Gateway Status -->
        <div class="node-status-row">
          <div class="status-badge ${isDownlink ? 'status-badge-success' : 'status-badge-error'}">
            <i class="fas ${isDownlink ? 'fa-check-circle' : 'fa-times-circle'}"></i>
            <span>Downlink</span>
          </div>
          <div class="status-badge status-badge-clickable ${isValidGateway ? 'status-badge-success' : 'status-badge-error'}"
               data-node-id="${nodeId}"
               data-node-name="${longName}"
               data-is-valid="${isValidGateway}"
               onclick="showValidationErrors(this)"
               title="${!isValidGateway ? 'Click to see validation errors' : ''}">
            <i class="fas ${isValidGateway ? 'fa-check-circle' : 'fa-times-circle'}"></i>
            <span>Valid GW</span>
          </div>
        </div>

        <!-- Connection Info -->
        <div class="node-info-row">
          <span class="node-info-text">${ipAddress}</span>
          <span class="node-info-text">${nodeRole}</span>
          <span class="node-info-text">${nodeId}</span>
        </div>
      </div>
    `;
  }).join('');
}

function renderNodesTable(nodes, isAdmin) {
  const tbody = document.getElementById('nodes-tbody');

  if (!tbody) {
    console.error('Nodes table body not found');
    return;
  }

  if (!nodes || nodes.length === 0) {
    tbody.innerHTML = '<tr><td colspan="' + (isAdmin ? '8' : '7') + '"><i>No nodes found</i></td></tr>';
    return;
  }

  // Store validation errors for later access
  nodeValidationErrors = {};
  nodes.forEach(node => {
    if (node.node_id && node.validation_errors) {
      nodeValidationErrors[node.node_id] = node.validation_errors;
    }
  });

  tbody.innerHTML = nodes.map(node => {
    const validationClass = node.validation_errors && node.validation_errors.length > 0 ? 'has-errors' : '';
    const validationTitle = node.validation_errors && node.validation_errors.length > 0
      ? 'Validation errors: ' + node.validation_errors.join(', ')
      : '';

    return `
      <tr class="${validationClass}" title="${validationTitle}">
        <td>${node.node_id || ''}</td>
        <td>${node.short_name || ''}</td>
        <td>${node.long_name || 'unknown'}</td>
        <td>${node.proxy_type || '<i>none</i>'}</td>
        <td>${node.is_connected ? node.address : '<i>disconnected</i>'}</td>
        <td>${node.is_downlink ? 'Yes' : 'No'}</td>
        <td>${node.is_valid_gateway ? 'Yes' : 'No'}</td>
        ${isAdmin ? `<td>${node.user_display || ''}</td>` : ''}
      </tr>
    `;
  }).join('');
}

function renderOtherClientsTable(clients, isAdmin) {
  const tbody = document.getElementById('other-clients-tbody');

  if (!clients || clients.length === 0) {
    tbody.innerHTML = '<tr><td colspan="' + (isAdmin ? '3' : '2') + '"><i>No other clients</i></td></tr>';
    return;
  }

  tbody.innerHTML = clients.map(client => `
    <tr>
      <td>${client.client_id}</td>
      <td>${client.address || '<i>disconnected</i>'}</td>
      ${isAdmin ? `<td>${client.user_display || ''}</td>` : ''}
    </tr>
  `).join('');
}

/**
 * SSE reconnection for filter changes
 */
function reconnectSSEWithFilters() {
  // Find the SSE-connected element (either node-grid for My Nodes or nodes-tbody for All Nodes)
  const nodeGrid = document.getElementById('node-grid');
  const nodesTbody = document.getElementById('nodes-tbody');
  const sseElement = nodeGrid || nodesTbody;
  const otherClientsTbody = document.getElementById('other-clients-tbody');

  if (!sseElement) return;

  // Build SSE URL with current filter state
  const params = new URLSearchParams();
  const connectedCheckbox = document.getElementById('filter-connected');
  const gatewayCheckbox = document.getElementById('filter-gateway');

  // Include filter-connected: for checkbox use .checked, for hidden use hasAttribute('checked')
  if (connectedCheckbox) {
    const isChecked = connectedCheckbox.type === 'hidden'
      ? connectedCheckbox.hasAttribute('checked')
      : connectedCheckbox.checked;
    if (isChecked) {
      params.append('filter-connected', 'on');
    }
  }
  if (gatewayCheckbox?.checked) {
    params.append('filter-gateway', 'on');
  }

  const isAdmin = typeof window.isAdmin !== 'undefined' && window.isAdmin;
  if (isAdmin) {
    params.append('all_users', 'true');
  }

  const sseUrl = '/api/nodes-sse' + (params.toString() ? '?' + params.toString() : '');

  // Update sse-connect attribute and trigger reconnection
  sseElement.setAttribute('sse-connect', sseUrl);
  if (otherClientsTbody) {
    // For other clients, append &type=other (use ? if no existing params)
    const separator = params.toString() ? '&' : '?';
    otherClientsTbody.setAttribute('sse-connect', sseUrl + separator + 'type=other');
  }

  // Trigger HTMX to reconnect SSE by removing and re-adding the extension
  if (typeof htmx !== 'undefined') {
    htmx.process(sseElement);
    if (otherClientsTbody) {
      htmx.process(otherClientsTbody);
    }
  }
}

// Attach event listeners for filters
document.addEventListener('DOMContentLoaded', function() {
  // Initialize wizard if onboarding modal exists
  const onboardingModal = document.getElementById('onboarding-modal');
  if (onboardingModal) {
    updateWizardUI();
  }

  const filterControls = ['filter-connected', 'filter-gateway'];

  filterControls.forEach(id => {
    const element = document.getElementById(id);
    if (element) {
      element.addEventListener('change', function() {
        // Reconnect SSE with new filter state
        reconnectSSEWithFilters();
      });
    }
  });

  // Auto-refresh toggle (admin only)
  const autoRefreshToggle = document.getElementById('auto-refresh');
  if (autoRefreshToggle) {
    autoRefreshToggle.addEventListener('change', function() {
      if (!this.checked && autoRefreshTimeout) {
        // Stop auto-refresh
        clearTimeout(autoRefreshTimeout);
        autoRefreshTimeout = null;
      } else if (this.checked) {
        // Start auto-refresh
        const isAdmin = typeof window.isAdmin !== 'undefined' ? window.isAdmin : false;
        scheduleNextRefresh(isAdmin);
      }
    });
  }
});