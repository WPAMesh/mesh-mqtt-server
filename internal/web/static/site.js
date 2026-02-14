/**
 * Debounce functions for better performance
 * (c) 2018 Chris Ferdinandi, MIT License, https://gomakethings.com
 * @param  {Function} fn The function to debounce
 * https://gomakethings.com/debouncing-your-javascript-events/
 */
var debounce=function(a){var e;return function(){var n=this,i=arguments;e&&window.cancelAnimationFrame(e),e=window.requestAnimationFrame(function(){a.apply(n,i)})}};

/**
 * SSE Manager - Vanilla JavaScript replacement for htmx SSE
 */
class NodeSSEManager {
  constructor() {
    this.eventSource = null;
    this.isAdmin = false;
    this.currentFilters = {};
    this.reconnectDelay = 5000;
    this.maxReconnectDelay = 30000;
  }

  connect(filters = {}) {
    this.disconnect();
    this.currentFilters = filters;

    const params = new URLSearchParams();
    if (filters.connectedOnly) params.append('filter-connected', 'on');
    if (filters.gatewayOnly) params.append('filter-gateway', 'on');
    if (this.isAdmin) params.append('all_users', 'true');

    const url = '/api/nodes-sse' + (params.toString() ? '?' + params.toString() : '');

    try {
      this.eventSource = new EventSource(url);
      this.reconnectDelay = 5000; // Reset delay on successful connection attempt

      this.eventSource.addEventListener('nodes-update', (e) => {
        const target = document.getElementById('node-grid') || document.getElementById('nodes-tbody');
        if (target) {
          // Preserve expanded state before updating
          const expandedIds = getExpandedNodeIds();

          target.innerHTML = e.data;

          // Restore expanded state after updating
          restoreExpandedState(expandedIds);

          // Execute any inline scripts (for validation errors)
          this.executeInlineScripts(target);
        }
      });

      this.eventSource.addEventListener('bridge-clients-update', (e) => {
        const target = document.getElementById('bridge-clients-tbody');
        if (target) {
          target.innerHTML = e.data;
        }
      });

      this.eventSource.addEventListener('other-clients-update', (e) => {
        const target = document.getElementById('other-clients-tbody');
        if (target) {
          target.innerHTML = e.data;
        }
      });

      this.eventSource.onerror = (e) => {
        console.warn('SSE connection error, will reconnect...');
        this.eventSource.close();
        // Exponential backoff for reconnection
        setTimeout(() => this.connect(this.currentFilters), this.reconnectDelay);
        this.reconnectDelay = Math.min(this.reconnectDelay * 1.5, this.maxReconnectDelay);
      };

      this.eventSource.onopen = () => {
        console.log('SSE connection established');
        this.reconnectDelay = 5000; // Reset on successful connection
      };
    } catch (error) {
      console.error('Failed to create EventSource:', error);
    }
  }

  disconnect() {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
  }

  executeInlineScripts(container) {
    // Find and execute any inline scripts (for validation errors data)
    container.querySelectorAll('script').forEach(script => {
      try {
        eval(script.textContent);
      } catch (e) {
        console.error('Error executing inline script:', e);
      }
    });
  }
}

// Global SSE manager instance
let sseManager = null;

function initSSE() {
  // Only initialize if we have SSE targets on the page
  const hasNodeGrid = document.getElementById('node-grid') !== null;
  const hasNodesTable = document.getElementById('nodes-tbody') !== null;

  if (!hasNodeGrid && !hasNodesTable) {
    return; // No SSE targets on this page
  }

  sseManager = new NodeSSEManager();
  sseManager.isAdmin = typeof window.isAdmin !== 'undefined' && window.isAdmin;

  // Get initial filter state
  const connectedCheckbox = document.getElementById('filter-connected');
  const gatewayCheckbox = document.getElementById('filter-gateway');

  const filters = {
    connectedOnly: connectedCheckbox ?
      (connectedCheckbox.type === 'hidden' ? connectedCheckbox.value === 'on' : connectedCheckbox.checked) :
      false,
    gatewayOnly: gatewayCheckbox?.checked || false
  };

  sseManager.connect(filters);
}

function reconnectSSEWithCurrentFilters() {
  if (!sseManager) return;

  const connectedCheckbox = document.getElementById('filter-connected');
  const gatewayCheckbox = document.getElementById('filter-gateway');

  const filters = {
    connectedOnly: connectedCheckbox ?
      (connectedCheckbox.type === 'hidden' ? connectedCheckbox.value === 'on' : connectedCheckbox.checked) :
      false,
    gatewayOnly: gatewayCheckbox?.checked || false
  };

  sseManager.connect(filters);
}

/**
 * Main code section
 */

/**
 * Mobile navigation toggle
 */
function toggleMobileNav() {
  const mobileNav = document.getElementById('mobile-nav');
  const burgerIcon = document.querySelector('.burger i');

  if (mobileNav) {
    mobileNav.classList.toggle('hidden');

    // Toggle burger icon
    if (burgerIcon) {
      burgerIcon.classList.toggle('fa-bars');
      burgerIcon.classList.toggle('fa-times');
    }
  }
}

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

/**
 * Toggle expanded state for node rows (mobile view)
 * @param {HTMLElement} row - The row element to toggle
 */
function toggleNodeRow(row) {
  // Only toggle on mobile viewport
  if (window.innerWidth > 768) return;

  // Toggle expanded class on the row
  row.classList.toggle('expanded');
}

/**
 * Get IDs of currently expanded node rows
 * @returns {string[]} Array of node IDs that are expanded
 */
function getExpandedNodeIds() {
  const expanded = document.querySelectorAll('.node-row.expanded');
  return Array.from(expanded).map(row => row.dataset.nodeId).filter(Boolean);
}

/**
 * Restore expanded state for node rows after SSE update
 * @param {string[]} nodeIds - Array of node IDs to expand
 */
function restoreExpandedState(nodeIds) {
  if (!nodeIds || nodeIds.length === 0) return;

  nodeIds.forEach(id => {
    const row = document.querySelector(`.node-row[data-node-id="${id}"]`);
    if (row) {
      row.classList.add('expanded');
    }
  });
}

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

    renderBridgeClientsTable(data.bridge_clients, isAdmin);
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

    const bridgeTbody = document.getElementById('bridge-clients-tbody');
    if (bridgeTbody) {
      bridgeTbody.innerHTML = '<tr><td colspan="' + (isAdmin ? '3' : '2') + '" class="error-message">Error loading clients</td></tr>';
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
    const nodeColor = node.node_color || '#808080'; // Default gray
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
      <div class="node-card mg-border mg-rounded1" style="--node-color: ${nodeColor}; --node-color-bg: ${nodeColor}26);">
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

function renderBridgeClientsTable(clients, isAdmin) {
  const tbody = document.getElementById('bridge-clients-tbody');

  if (!tbody) return;

  if (!clients || clients.length === 0) {
    tbody.innerHTML = '<tr><td colspan="' + (isAdmin ? '3' : '2') + '"><i>No bridge clients</i></td></tr>';
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

// Attach event listeners and initialize SSE
document.addEventListener('DOMContentLoaded', function() {
  // Initialize wizard if onboarding modal exists
  const onboardingModal = document.getElementById('onboarding-modal');
  if (onboardingModal) {
    updateWizardUI();
  }

  // Initialize SSE for node/client updates
  initSSE();

  // Filter change handlers - reconnect SSE with new filters
  const filterControls = ['filter-connected', 'filter-gateway'];
  filterControls.forEach(id => {
    const element = document.getElementById(id);
    if (element) {
      element.addEventListener('change', function() {
        reconnectSSEWithCurrentFilters();
      });
    }
  });

  // Auto-refresh toggle (admin only) - kept for manual refresh option
  const autoRefreshToggle = document.getElementById('auto-refresh');
  if (autoRefreshToggle) {
    autoRefreshToggle.addEventListener('change', function() {
      if (!this.checked && autoRefreshTimeout) {
        clearTimeout(autoRefreshTimeout);
        autoRefreshTimeout = null;
      } else if (this.checked) {
        const isAdmin = typeof window.isAdmin !== 'undefined' ? window.isAdmin : false;
        scheduleNextRefresh(isAdmin);
      }
    });
  }

  // Initialize users table if present (replaces htmx hx-trigger="load")
  initUsersTable();
});

/**
 * Users table initialization (vanilla JS replacement for htmx)
 */
async function initUsersTable() {
  const usersTbody = document.getElementById('users-tbody');
  if (!usersTbody) return;

  try {
    const response = await fetch('/api/users-html');
    if (response.ok) {
      usersTbody.innerHTML = await response.text();
    }
  } catch (error) {
    console.error('Error loading users:', error);
    usersTbody.innerHTML = '<tr><td colspan="6" class="error-message">Error loading users</td></tr>';
  }
}

// Function to refresh users table (called after edits/deletes)
async function refreshUsersTable() {
  await initUsersTable();
}