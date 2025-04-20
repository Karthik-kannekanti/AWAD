// Autonomous WAF Demo - Toolbox JavaScript

// Initialize when the document is ready
$(document).ready(function() {
    // Make the toolbox draggable and resizable
    $("#toolbox").draggable({
        handle: ".toolbox-header",
        containment: "window"
    }).resizable({
        minWidth: 300,
        minHeight: 300,
        maxWidth: 800,
        maxHeight: 800,
        handles: "all"
    });
    
    // Toolbox toggle button
    $("#toolbox-toggle").click(function() {
        $("#toolbox").toggle();
    });
    
    // Minimize toolbox
    $("#minimize-toolbox").click(function() {
        $("#toolbox").toggleClass("minimized");
    });
    
    // Expand toolbox
    $("#expand-toolbox").click(function() {
        $("#toolbox").toggleClass("expanded");
    });
    
    // Close toolbox
    $("#close-toolbox").click(function() {
        $("#toolbox").hide();
    });
    
    // Initialize Socket.IO connection
    const socket = io();
    
    // Listen for stats updates
    socket.on('stats_update', function(data) {
        updateStats(data);
    });
    
    // Listen for new log entries
    socket.on('new_log', function(data) {
        addLogEntry(data);
        updateStatsChart();
    });
    
    // Initialize stats
    fetchStats();
    
    // Initialize stats chart
    initStatsChart();
    
    // Set up attack simulation buttons
    $(".attack-btn").click(function() {
        const attackType = $(this).data("attack");
        let payload = "";
        
        if (attackType === "custom") {
            payload = $("#custom-payload").val();
            if (!payload) {
                alert("Please enter a custom payload");
                return;
            }
        }
        
        simulateAttack(attackType, payload);
    });
});

// Fetch current WAF statistics
function fetchStats() {
    $.ajax({
        url: '/api/stats',
        method: 'GET',
        success: function(data) {
            // Update stats display
            $("#total-requests").text(data.total_requests);
            $("#blocked-requests").text(data.blocked_requests);
            $("#anomalous-requests").text(data.anomalous_requests);
            
            // Update logs table
            $("#logs-table-body").empty();
            data.recent_logs.forEach(function(log) {
                addLogEntry(log);
            });
            
            // Update stats chart
            updateStatsChart(data);
        },
        error: function(error) {
            console.error("Error fetching stats:", error);
        }
    });
}

// Update statistics display
function updateStats(data) {
    $("#total-requests").text(data.total_requests);
    $("#blocked-requests").text(data.blocked_requests);
    $("#anomalous-requests").text(data.anomalous_requests);
}

// Add a log entry to the logs table
function addLogEntry(log) {
    // Create status badge
    let statusBadge = log.is_blocked ? 
        '<span class="badge bg-danger">Blocked</span>' : 
        '<span class="badge bg-success">Allowed</span>';
    
    // Create attack type badge
    let attackType = log.attack_type === 'none' || !log.attack_type ? 'None' : log.attack_type.replace('_', ' ');
    let attackBadge = log.attack_type === 'none' || !log.attack_type ? 
        '<span class="badge bg-secondary">None</span>' : 
        `<span class="badge bg-warning">${attackType}</span>`;
    
    // Format timestamp
    let timestamp = log.timestamp;
    
    // Create table row
    const row = `
        <tr data-log-id="${log.id}">
            <td>${timestamp}</td>
            <td>${log.method}</td>
            <td>${truncateText(log.path, 30)}</td>
            <td>${statusBadge}</td>
            <td>${attackBadge}</td>
        </tr>
    `;
    
    // Add to the beginning of the table
    $("#logs-table-body").prepend(row);
    
    // Keep only the last 10 rows
    if ($("#logs-table-body tr").length > 10) {
        $("#logs-table-body tr:last").remove();
    }
}

// Initialize the stats chart
let statsChart;
function initStatsChart() {
    const ctx = document.getElementById('stats-chart').getContext('2d');
    statsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Total', 'Blocked', 'Anomalies'],
            datasets: [{
                label: 'Requests',
                data: [0, 0, 0],
                backgroundColor: [
                    'rgba(13, 110, 253, 0.5)',
                    'rgba(220, 53, 69, 0.5)',
                    'rgba(255, 193, 7, 0.5)'
                ],
                borderColor: [
                    'rgba(13, 110, 253, 1)',
                    'rgba(220, 53, 69, 1)',
                    'rgba(255, 193, 7, 1)'
                ],
                borderWidth: 1
            }]
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
}

// Update the stats chart
function updateStatsChart(data) {
    if (!data) {
        // If no data provided, fetch it
        $.ajax({
            url: '/api/stats',
            method: 'GET',
            success: function(data) {
                updateChartWithData(data);
            }
        });
    } else {
        updateChartWithData(data);
    }
}

// Update chart with the provided data
function updateChartWithData(data) {
    statsChart.data.datasets[0].data = [
        data.total_requests,
        data.blocked_requests,
        data.anomalous_requests
    ];
    statsChart.update();
}

// Simulate an attack
function simulateAttack(attackType, customPayload) {
    // Show loading state
    $("#attack-result").html(`
        <div class="card">
            <div class="card-header">
                <h6>Attack Simulation Result</h6>
            </div>
            <div class="card-body text-center">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <p class="mt-2">Simulating ${attackType.replace('_', ' ')} attack...</p>
            </div>
        </div>
    `);
    
    // Send attack simulation request
    $.ajax({
        url: '/api/simulate-attack',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            attack_type: attackType,
            custom_payload: customPayload
        }),
        success: function(data) {
            // Display result
            let statusClass = data.was_blocked ? 'success' : 'danger';
            let statusText = data.was_blocked ? 'Blocked' : 'Not Blocked';
            let icon = data.was_blocked ? 'check-circle' : 'exclamation-triangle';
            
            // Get detection info
            let detectionInfo = '';
            if (data.detected_as && data.detected_as !== 'none') {
                detectionInfo = `<p><strong>Detected as:</strong> ${data.detected_as.replace('_', ' ')}</p>`;
            }
            
            $("#attack-result").html(`
                <div class="card">
                    <div class="card-header">
                        <h6>Attack Simulation Result</h6>
                    </div>
                    <div class="card-body">
                        <div class="text-center mb-3">
                            <i class="fas fa-${icon} text-${statusClass}" style="font-size: 3rem;"></i>
                            <h5 class="mt-2 text-${statusClass}">${statusText}</h5>
                        </div>
                        <div class="attack-details">
                            <p><strong>Attack Type:</strong> ${data.attack_type.replace('_', ' ')}</p>
                            <p><strong>Payload:</strong> <code>${escapeHtml(data.payload)}</code></p>
                            ${detectionInfo}
                        </div>
                    </div>
                </div>
            `);
            
            // Refresh stats after attack
            fetchStats();
        },
        error: function(error) {
            console.error("Error simulating attack:", error);
            $("#attack-result").html(`
                <div class="card">
                    <div class="card-header">
                        <h6>Attack Simulation Result</h6>
                    </div>
                    <div class="card-body">
                        <div class="text-center text-danger mb-3">
                            <i class="fas fa-times-circle" style="font-size: 3rem;"></i>
                            <h5 class="mt-2">Simulation Failed</h5>
                        </div>
                        <p>Error simulating attack. Please try again.</p>
                        <p class="small text-muted">Details: ${error.responseJSON ? error.responseJSON.message : 'Unknown error'}</p>
                    </div>
                </div>
            `);
        }
    });
}

// Helper function to truncate text
function truncateText(text, maxLength) {
    if (!text) return '';
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
}

// Helper function to escape HTML
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
