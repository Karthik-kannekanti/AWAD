// Autonomous WAF Demo - Dashboard JavaScript

// Global variables
let timeSeriesChart;
let attackTypesChart;
let currentPage = 1;
let totalPages = 1;
let currentFilters = {
    attack_type: 'all',
    is_blocked: null,
    is_anomaly: null,
    search: ''
};
let socket;

// Initialize when the document is ready
$(document).ready(function() {
    // Initialize Socket.IO connection
    initializeSocketConnection();
    
    // Initialize stats
    fetchStats();
    
    // Initialize logs
    fetchLogs();
    
    // Initialize charts
    initCharts();
    
    // Set up filter button
    $("#apply-filters").click(function() {
        currentFilters = {
            attack_type: $("#attack-type-filter").val(),
            is_blocked: $("#status-filter").val() === 'all' ? null : ($("#status-filter").val() === 'blocked'),
            is_anomaly: $("#anomaly-filter").val() === 'all' ? null : ($("#anomaly-filter").val() === 'true'),
            search: $("#search-filter").val(),
            start_date: $("#start-date").val(),
            end_date: $("#end-date").val()
        };
        currentPage = 1;
        fetchLogs();
    });
    
    // Set up log details modal
    $(document).on('click', '#logs-table-body tr', function() {
        const logId = $(this).data('log-id');
        showLogDetails(logId);
    });
    
    // Set up feedback buttons
    $("#mark-as-attack").click(function() {
        const logId = $(this).data('log-id');
        submitFeedback(logId, true);
    });
    
    $("#mark-as-legitimate").click(function() {
        const logId = $(this).data('log-id');
        submitFeedback(logId, false);
    });
    
    // Set up clear logs button
    $("#clear-logs-btn").click(function() {
        if (confirm("Are you sure you want to clear all logs? This cannot be undone.")) {
            clearAllLogs();
        }
    });
    
    // Set up export logs button
    $("#export-logs-btn").click(function() {
        exportLogs();
    });
    
    // Set up auto-refresh toggle
    $("#auto-refresh").change(function() {
        if ($(this).prop('checked')) {
            // Start auto-refresh
            window.autoRefreshInterval = setInterval(function() {
                fetchStats();
                if (currentPage === 1) {
                    fetchLogs();
                }
            }, 10000); // Refresh every 10 seconds
        } else {
            // Stop auto-refresh
            clearInterval(window.autoRefreshInterval);
        }
    });
    
    // Update current time
    updateCurrentTime();
    setInterval(updateCurrentTime, 1000);
});

// Initialize Socket.IO connection
function initializeSocketConnection() {
    // Get the current hostname and port
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname;
    const port = window.location.port;
    
    // Try to connect to the WAF application's WebSocket server
    try {
        socket = io();
        
        // Listen for stats updates
        socket.on('stats_update', function(data) {
            console.log('Received stats update:', data);
            updateStats(data);
        });
        
        // Listen for new log entries
        socket.on('new_log', function(data) {
            console.log('Received new log:', data);
            // Add the new log to the top of the table if we're on the first page
            if (currentPage === 1) {
                prependNewLog(data);
            }
            
            // Always update stats
            fetchStats();
        });
        
        // Listen for feedback updates
        socket.on('feedback_update', function(data) {
            console.log('Received feedback update:', data);
            // Update the feedback status in the logs table
            updateFeedbackStatus(data.log_id, data.is_attack);
        });
        
        // Listen for logs cleared event
        socket.on('logs_cleared', function(data) {
            console.log('Logs cleared:', data);
            // Refresh everything
            fetchStats();
            fetchLogs();
        });
        
        // Handle connection status
        socket.on('connect', function() {
            console.log('Connected to WebSocket server');
            $('#connection-status').html('<span class="badge bg-success">Connected</span>');
        });
        
        socket.on('disconnect', function() {
            console.log('Disconnected from WebSocket server');
            $('#connection-status').html('<span class="badge bg-danger">Disconnected</span>');
        });
        
        socket.on('connect_error', function(error) {
            console.error('WebSocket connection error:', error);
            $('#connection-status').html('<span class="badge bg-warning">Connection Error</span>');
        });
    } catch (error) {
        console.error('Error initializing Socket.IO:', error);
        $('#connection-status').html('<span class="badge bg-danger">Connection Failed</span>');
    }
}

// Update current time display
function updateCurrentTime() {
    const now = new Date();
    $("#current-time").text(now.toLocaleString());
}

// Fetch current WAF statistics
function fetchStats() {
    $.ajax({
        url: '/api/stats',
        method: 'GET',
        success: function(data) {
            // Update stats display
            updateStats(data);
        },
        error: function(error) {
            console.error("Error fetching stats:", error);
            showNotification('Error fetching statistics', 'danger');
        }
    });
}

// Update stats display with animation
function updateStats(data) {
    // Store old values for animation
    const oldValues = {
        total: parseInt($("#total-requests").text()) || 0,
        blocked: parseInt($("#blocked-requests").text()) || 0,
        anomalous: parseInt($("#anomalous-requests").text()) || 0,
        attackTypes: parseInt($("#attack-types-count").text()) || 0
    };
    
    // Update with new values
    $("#total-requests").text(data.total_requests);
    $("#blocked-requests").text(data.blocked_requests);
    $("#anomalous-requests").text(data.anomalous_requests);
    
    // Count attack types
    const attackTypesCount = Object.keys(data.attack_types).length;
    $("#attack-types-count").text(attackTypesCount);
    
    // Update attack success rate if available
    if (data.attack_success_rate !== undefined) {
        $("#attack-success-rate").text(data.attack_success_rate.toFixed(1) + '%');
    }
    
    // Add animation class if values changed
    if (oldValues.total !== data.total_requests) {
        $("#total-requests").addClass("updated");
        setTimeout(() => $("#total-requests").removeClass("updated"), 1000);
    }
    
    if (oldValues.blocked !== data.blocked_requests) {
        $("#blocked-requests").addClass("updated");
        setTimeout(() => $("#blocked-requests").removeClass("updated"), 1000);
    }
    
    if (oldValues.anomalous !== data.anomalous_requests) {
        $("#anomalous-requests").addClass("updated");
        setTimeout(() => $("#anomalous-requests").removeClass("updated"), 1000);
    }
    
    if (oldValues.attackTypes !== attackTypesCount) {
        $("#attack-types-count").addClass("updated");
        setTimeout(() => $("#attack-types-count").removeClass("updated"), 1000);
    }
    
    // Update recent attacks if available
    if (data.recent_attacks && data.recent_attacks.length > 0) {
        updateRecentAttacks(data.recent_attacks);
    }
    
    // Update charts
    updateCharts(data);
    
    // Update top IPs
    updateTopIPs(data.top_ips);
    
    // Update top paths
    updateTopPaths(data.top_paths);
}

// Prepend a new log entry to the logs table
function prependNewLog(log) {
    // Format the log for display
    let statusBadge = log.is_blocked ? 
        '<span class="badge bg-danger">Blocked</span>' : 
        '<span class="badge bg-success">Allowed</span>';
    
    let attackType = log.attack_type === 'none' || !log.attack_type ? 'None' : log.attack_type.replace('_', ' ');
    let attackBadge = log.attack_type === 'none' || !log.attack_type ? 
        '<span class="badge bg-secondary">None</span>' : 
        `<span class="badge bg-warning">${attackType}</span>`;
    
    let anomalyBadge = log.is_anomaly ? 
        '<span class="badge bg-warning"><i class="fas fa-exclamation-triangle"></i></span>' : 
        '<span class="badge bg-secondary"><i class="fas fa-check"></i></span>';
    
    // Create table row with highlight effect
    const row = `
        <tr data-log-id="${log.id}" style="cursor: pointer;" class="new-log-highlight">
            <td>${log.timestamp}</td>
            <td>${log.ip}</td>
            <td>${log.method}</td>
            <td>${truncateText(log.path, 30)}</td>
            <td>${statusBadge}</td>
            <td>${attackBadge}</td>
            <td>${anomalyBadge}</td>
            <td>
                <button class="btn btn-sm btn-outline-primary view-log-btn" data-log-id="${log.id}">
                    <i class="fas fa-eye"></i>
                </button>
            </td>
        </tr>
    `;
    
    // Add to the beginning of the table
    $("#logs-table-body").prepend(row);
    
    // Remove highlight after animation
    setTimeout(function() {
        $(".new-log-highlight").removeClass("new-log-highlight");
    }, 3000);
    
    // Keep only the displayed number of rows
    const maxRows = 50;
    if ($("#logs-table-body tr").length > maxRows) {
        $("#logs-table-body tr:last").remove();
    }
    
    // Update log count
    const currentCount = parseInt($("#logs-count").text()) || 0;
    $("#logs-count").text(currentCount + 1);
    
    // Show notification
    showNotification('New request logged', log.is_blocked ? 'danger' : 'success');
}

// Update recent attacks list with animation
function updateRecentAttacks(recentAttacks) {
    const recentAttacksList = $("#recent-attacks-list");
    recentAttacksList.empty();
    
    recentAttacks.forEach(function(attack, index) {
        const attackType = attack.attack_type.replace('_', ' ');
        const delay = index * 100; // Stagger animations
        
        const listItem = $(`
            <li class="list-group-item d-flex justify-content-between align-items-center recent-attack-item" style="opacity: 0;">
                <div>
                    <span class="badge bg-danger">${attackType}</span>
                    <small class="ms-2">${attack.timestamp}</small>
                </div>
                <button class="btn btn-sm btn-outline-primary view-log-btn" data-log-id="${attack.id}">
                    <i class="fas fa-eye"></i>
                </button>
            </li>
        `);
        
        recentAttacksList.append(listItem);
        
        // Animate in with delay
        setTimeout(() => {
            listItem.css({
                'opacity': '1',
                'transform': 'translateX(0)'
            });
        }, delay);
    });
}

// Update top IPs list with animation
function updateTopIPs(topIPs) {
    const topIPsList = $("#top-ips-list");
    topIPsList.empty();
    
    if (topIPs && topIPs.length > 0) {
        topIPs.forEach(function(item, index) {
            const delay = index * 50; // Stagger animations
            
            const listItem = $(`
                <li class="list-group-item d-flex justify-content-between align-items-center" style="opacity: 0; transform: translateY(10px);">
                    <span>${item.ip}</span>
                    <span class="badge bg-primary rounded-pill">${item.count}</span>
                </li>
            `);
            
            topIPsList.append(listItem);
            
            // Animate in with delay
            setTimeout(() => {
                listItem.css({
                    'opacity': '1',
                    'transform': 'translateY(0)'
                });
                listItem.css('transition', 'all 0.3s ease-in-out');
            }, delay);
        });
    } else {
        topIPsList.html('<li class="list-group-item text-center text-muted">No data available</li>');
    }
}

// Update top paths list with animation
function updateTopPaths(topPaths) {
    const topPathsList = $("#top-paths-list");
    topPathsList.empty();
    
    if (topPaths && topPaths.length > 0) {
        topPaths.forEach(function(item, index) {
            const delay = index * 50; // Stagger animations
            
            const listItem = $(`
                <li class="list-group-item d-flex justify-content-between align-items-center" style="opacity: 0; transform: translateY(10px);">
                    <span>${truncateText(item.path, 25)}</span>
                    <span class="badge bg-primary rounded-pill">${item.count}</span>
                </li>
            `);
            
            topPathsList.append(listItem);
            
            // Animate in with delay
            setTimeout(() => {
                listItem.css({
                    'opacity': '1',
                    'transform': 'translateY(0)'
                });
                listItem.css('transition', 'all 0.3s ease-in-out');
            }, delay);
        });
    } else {
        topPathsList.html('<li class="list-group-item text-center text-muted">No data available</li>');
    }
}

// Fetch logs with pagination and filtering
function fetchLogs() {
    const params = {
        page: currentPage,
        per_page: 50,
        ...currentFilters
    };
    
    $.ajax({
        url: '/api/logs',
        method: 'GET',
        data: params,
        success: function(data) {
            // Update logs table
            updateLogsTable(data.logs);
            
            // Update pagination
            updatePagination(data.page, data.total_pages, data.total);
        },
        error: function(error) {
            console.error("Error fetching logs:", error);
            showNotification('Error fetching logs', 'danger');
        }
    });
}

// Update logs table with data
function updateLogsTable(logs) {
    $("#logs-table-body").empty();
    
    logs.forEach(function(log) {
        // Create status badge
        let statusBadge = log.is_blocked ? 
            '<span class="badge bg-danger">Blocked</span>' : 
            '<span class="badge bg-success">Allowed</span>';
        
        // Create attack type badge
        let attackType = log.attack_type === 'none' || !log.attack_type ? 'None' : log.attack_type.replace('_', ' ');
        let attackBadge = log.attack_type === 'none' || !log.attack_type ? 
            '<span class="badge bg-secondary">None</span>' : 
            `<span class="badge bg-warning">${attackType}</span>`;
        
        // Create anomaly badge
        let anomalyBadge = log.is_anomaly ? 
            '<span class="badge bg-warning"><i class="fas fa-exclamation-triangle"></i></span>' : 
            '<span class="badge bg-secondary"><i class="fas fa-check"></i></span>';
        
        // Format timestamp
        let timestamp = log.timestamp;
        
        // Create table row
        const row = `
            <tr data-log-id="${log.id}" style="cursor: pointer;">
                <td>${timestamp}</td>
                <td>${log.ip}</td>
                <td>${log.method}</td>
                <td>${truncateText(log.path, 30)}</td>
                <td>${statusBadge}</td>
                <td>${attackBadge}</td>
                <td>${anomalyBadge}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary view-log-btn" data-log-id="${log.id}">
                        <i class="fas fa-eye"></i>
                    </button>
                </td>
            </tr>
        `;
        
        $("#logs-table-body").append(row);
    });
}

// Update pagination controls
function updatePagination(page, totalPages, totalLogs) {
    currentPage = page;
    this.totalPages = totalPages;
    
    // Update logs count
    $("#logs-count").text(totalLogs);
    
    // Generate pagination controls
    const pagination = $("#logs-pagination");
    pagination.empty();
    
    // Previous button
    pagination.append(`
        <li class="page-item ${page === 1 ? 'disabled' : ''}">
            <a class="page-link" href="#" data-page="${page - 1}" aria-label="Previous">
                <span aria-hidden="true">&laquo;</span>
            </a>
        </li>
    `);
    
    // Page numbers
    const startPage = Math.max(1, page - 2);
    const endPage = Math.min(totalPages, page + 2);
    
    for (let i = startPage; i <= endPage; i++) {
        pagination.append(`
            <li class="page-item ${i === page ? 'active' : ''}">
                <a class="page-link" href="#" data-page="${i}">${i}</a>
            </li>
        `);
    }
    
    // Next button
    pagination.append(`
        <li class="page-item ${page === totalPages ? 'disabled' : ''}">
            <a class="page-link" href="#" data-page="${page + 1}" aria-label="Next">
                <span aria-hidden="true">&raquo;</span>
            </a>
        </li>
    `);
    
    // Set up page click handlers
    $(".page-link").click(function(e) {
        e.preventDefault();
        const newPage = $(this).data('page');
        if (newPage >= 1 && newPage <= totalPages) {
            currentPage = newPage;
            fetchLogs();
        }
    });
}

// Initialize charts
function initCharts() {
    // Time series chart
    const timeSeriesCtx = document.getElementById('time-series-chart').getContext('2d');
    timeSeriesChart = new Chart(timeSeriesCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Total Requests',
                    data: [],
                    borderColor: 'rgba(13, 110, 253, 1)',
                    backgroundColor: 'rgba(13, 110, 253, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Blocked Requests',
                    data: [],
                    borderColor: 'rgba(220, 53, 69, 1)',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Anomalous Requests',
                    data: [],
                    borderColor: 'rgba(255, 193, 7, 1)',
                    backgroundColor: 'rgba(255, 193, 7, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });
    
    // Attack types chart
    const attackTypesCtx = document.getElementById('attack-types-chart').getContext('2d');
    attackTypesChart = new Chart(attackTypesCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    'rgba(220, 53, 69, 0.8)',
                    'rgba(255, 193, 7, 0.8)',
                    'rgba(13, 110, 253, 0.8)',
                    'rgba(32, 201, 151, 0.8)',
                    'rgba(111, 66, 193, 0.8)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right'
                }
            }
        }
    });
}

// Update charts with new data
function updateCharts(data) {
    // Update time series chart
    if (data.time_series && data.time_series.length > 0) {
        const labels = data.time_series.map(item => {
            const date = new Date(item.hour);
            return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        });
        
        const totalData = data.time_series.map(item => item.count);
        const blockedData = data.time_series.map(item => item.blocked);
        const anomalousData = data.time_series.map(item => item.anomalous);
        
        timeSeriesChart.data.labels = labels;
        timeSeriesChart.data.datasets[0].data = totalData;
        timeSeriesChart.data.datasets[1].data = blockedData;
        timeSeriesChart.data.datasets[2].data = anomalousData;
        timeSeriesChart.update();
    }
    
    // Update attack types chart
    if (data.attack_types) {
        const labels = Object.keys(data.attack_types).map(key => key.replace('_', ' '));
        const values = Object.values(data.attack_types);
        
        attackTypesChart.data.labels = labels;
        attackTypesChart.data.datasets[0].data = values;
        attackTypesChart.update();
    }
}

// Show log details in modal
function showLogDetails(logId) {
    // Find the log in the current logs
    $.ajax({
        url: '/api/logs',
        method: 'GET',
        data: { page: 1, per_page: 1, search: `id:${logId}` },
        success: function(data) {
            if (data.logs && data.logs.length > 0) {
                const log = data.logs[0];
                
                // Set modal content
                $("#modal-id").text(log.id);
                $("#modal-time").text(log.timestamp);
                $("#modal-ip").text(log.ip);
                $("#modal-method").text(log.method);
                $("#modal-path").text(log.path);
                
                // Set status
                const statusText = log.is_blocked ? 'Blocked' : 'Allowed';
                const statusClass = log.is_blocked ? 'danger' : 'success';
                $("#modal-status").html(`<span class="badge bg-${statusClass}">${statusText}</span>`);
                
                // Set attack type
                const attackType = log.attack_type === 'none' || !log.attack_type ? 'None' : log.attack_type.replace('_', ' ');
                const attackClass = log.attack_type === 'none' || !log.attack_type ? 'secondary' : 'warning';
                $("#modal-attack-type").html(`<span class="badge bg-${attackClass}">${attackType}</span>`);
                
                // Set anomaly
                const anomalyText = log.is_anomaly ? 'Yes' : 'No';
                const anomalyClass = log.is_anomaly ? 'warning' : 'secondary';
                $("#modal-anomaly").html(`<span class="badge bg-${anomalyClass}">${anomalyText}</span>`);
                
                // Set user agent
                $("#modal-user-agent").text(log.user_agent || 'Not available');
                
                // Set payload
                let payloadText = 'Not available';
                if (log.payload) {
                    try {
                        const payload = typeof log.payload === 'string' ? JSON.parse(log.payload) : log.payload;
                        payloadText = JSON.stringify(payload, null, 2);
                    } catch (e) {
                        payloadText = log.payload;
                    }
                }
                $("#modal-payload").text(payloadText);
                
                // Set feedback buttons data
                $("#mark-as-attack").data('log-id', log.id);
                $("#mark-as-legitimate").data('log-id', log.id);
                
                // Update feedback buttons based on current feedback
                updateFeedbackButtons(log.feedback);
                
                // Show the modal
                const logDetailsModal = new bootstrap.Modal(document.getElementById('logDetailsModal'));
                logDetailsModal.show();
            }
        }
    });
}

// Update feedback buttons based on current feedback
function updateFeedbackButtons(feedback) {
    if (feedback === 1) {
        // Marked as attack
        $("#mark-as-attack").addClass('active btn-danger').removeClass('btn-outline-danger');
        $("#mark-as-legitimate").removeClass('active btn-success').addClass('btn-outline-success');
    } else if (feedback === 0) {
        // Marked as legitimate
        $("#mark-as-attack").removeClass('active btn-danger').addClass('btn-outline-danger');
        $("#mark-as-legitimate").addClass('active btn-success').removeClass('btn-outline-success');
    } else {
        // No feedback yet
        $("#mark-as-attack").removeClass('active btn-danger').addClass('btn-outline-danger');
        $("#mark-as-legitimate").removeClass('active btn-success').addClass('btn-outline-success');
    }
}

// Submit feedback for a log entry
function submitFeedback(logId, isAttack) {
    $.ajax({
        url: '/api/feedback',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            log_id: logId,
            is_attack: isAttack
        }),
        success: function(data) {
            // Update feedback buttons
            updateFeedbackButtons(isAttack ? 1 : 0);
            
            // Show success message
            alert(`Feedback submitted: ${isAttack ? 'Attack' : 'Legitimate'}`);
        },
        error: function(error) {
            console.error("Error submitting feedback:", error);
            alert("Error submitting feedback. Please try again.");
        }
    });
}

// Update feedback status in the logs table
function updateFeedbackStatus(logId, isAttack) {
    // This would update the UI if needed
    // For now, we just refresh the logs if the feedback changes
    fetchLogs();
}

// Helper function to truncate text
function truncateText(text, maxLength) {
    if (!text) return '';
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
}

// Show notification
function showNotification(message, type = 'info') {
    // Create notification element if it doesn't exist
    if ($("#notification-container").length === 0) {
        $("body").append('<div id="notification-container" style="position: fixed; top: 20px; right: 20px; z-index: 9999;"></div>');
    }
    
    // Create notification
    const id = 'notification-' + Date.now();
    const notification = `
        <div id="${id}" class="toast align-items-center text-white bg-${type} border-0" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="d-flex">
                <div class="toast-body">
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        </div>
    `;
    
    // Add to container
    $("#notification-container").append(notification);
    
    // Initialize and show toast
    const toast = new bootstrap.Toast(document.getElementById(id), {
        delay: 3000
    });
    toast.show();
}
