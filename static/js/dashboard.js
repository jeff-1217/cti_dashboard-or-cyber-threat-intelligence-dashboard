// Dashboard JavaScript for CTI Dashboard

let categoryChart = null;
let timelineChart = null;

// Load dashboard data on page load
document.addEventListener('DOMContentLoaded', function() {
    loadDashboardStats();
    setInterval(loadDashboardStats, 60000); // Refresh every minute
});

async function loadDashboardStats() {
    try {
        const response = await fetch('/api/dashboard/stats');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        
        // Check for API errors
        if (data.error) {
            console.error('API Error:', data.error);
            document.getElementById('total-threats').textContent = '0';
            document.getElementById('high-risk').textContent = '0';
            document.getElementById('medium-risk').textContent = '0';
            document.getElementById('low-risk').textContent = '0';
            updateTopIPsTable([]);
            updateCategoryChart({});
            updateTimelineChart([]);
            return;
        }
        
        // Update stats cards
        document.getElementById('total-threats').textContent = data.total_threats || 0;
        
        // Calculate risk levels from all threats, not just top IPs
        // For now, we'll use top IPs as a proxy, but ideally we'd get this from the API
        const topIps = data.top_malicious_ips || [];
        const highRisk = topIps.filter(ip => ip.threat_score > 70).length;
        const mediumRisk = topIps.filter(ip => ip.threat_score > 40 && ip.threat_score <= 70).length;
        const lowRisk = topIps.filter(ip => ip.threat_score <= 40).length;
        
        document.getElementById('high-risk').textContent = highRisk;
        document.getElementById('medium-risk').textContent = mediumRisk;
        document.getElementById('low-risk').textContent = lowRisk;
        
        // Update top IPs table
        updateTopIPsTable(topIps);
        
        // Update charts
        updateCategoryChart(data.category_counts || {});
        updateTimelineChart(data.threats_over_time || []);
        
    } catch (error) {
        console.error('Error loading dashboard stats:', error);
        // Show error state
        document.getElementById('total-threats').textContent = 'Error';
        document.getElementById('high-risk').textContent = '-';
        document.getElementById('medium-risk').textContent = '-';
        document.getElementById('low-risk').textContent = '-';
        updateTopIPsTable([]);
    }
}

function updateTopIPsTable(ips) {
    const tbody = document.getElementById('top-ips-table');
    
    if (!ips || ips.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No threats found. Use the Lookup page to check IPs or domains.</td></tr>';
        return;
    }
    
    tbody.innerHTML = ips.map(ip => `
        <tr>
            <td><code>${ip.ip || 'N/A'}</code></td>
            <td>
                <span class="badge ${getScoreBadgeClass(ip.threat_score || 0)}">
                    ${ip.threat_score || 0}
                </span>
            </td>
            <td>${ip.confidence || 0}</td>
            <td>${ip.country || 'Unknown'}</td>
            <td>${(ip.tags && ip.tags.length > 0) ? ip.tags.map(tag => `<span class="badge bg-secondary me-1">${tag}</span>`).join('') : '<span class="text-muted">None</span>'}</td>
        </tr>
    `).join('');
}

function getScoreBadgeClass(score) {
    if (score >= 70) return 'bg-danger';
    if (score >= 40) return 'bg-warning';
    return 'bg-success';
}

function updateCategoryChart(categoryData) {
    const ctx = document.getElementById('categoryChart').getContext('2d');
    
    // Handle empty data
    if (!categoryData || Object.keys(categoryData).length === 0) {
        if (categoryChart) {
            categoryChart.destroy();
            categoryChart = null;
        }
        ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);
        ctx.fillStyle = '#94a3b8';
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No threat categories found', ctx.canvas.width / 2, ctx.canvas.height / 2);
        return;
    }
    
    const labels = Object.keys(categoryData);
    const values = Object.values(categoryData);
    const colors = generateColors(labels.length);
    
    if (categoryChart) {
        categoryChart.destroy();
    }
    
    categoryChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                label: 'Threat Categories',
                data: values,
                backgroundColor: colors,
                borderColor: '#0f0f23',
                borderWidth: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#f8fafc',
                        padding: 15,
                        font: {
                            size: 12
                        }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(22, 33, 62, 0.95)',
                    titleColor: '#f8fafc',
                    bodyColor: '#cbd5e1',
                    borderColor: '#1e293b',
                    borderWidth: 1
                }
            }
        }
    });
}

function updateTimelineChart(timelineData) {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    
    // Handle empty data
    if (!timelineData || timelineData.length === 0) {
        if (timelineChart) {
            timelineChart.destroy();
            timelineChart = null;
        }
        ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);
        ctx.fillStyle = '#94a3b8';
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No timeline data available', ctx.canvas.width / 2, ctx.canvas.height / 2);
        return;
    }
    
    const labels = timelineData.map(item => item.date);
    const counts = timelineData.map(item => item.count);
    
    if (timelineChart) {
        timelineChart.destroy();
    }
    
    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Threats',
                data: counts,
                borderColor: '#00d4ff',
                backgroundColor: 'rgba(0, 212, 255, 0.1)',
                borderWidth: 3,
                fill: true,
                tension: 0.4,
                pointRadius: 4,
                pointHoverRadius: 6,
                pointBackgroundColor: '#00d4ff',
                pointBorderColor: '#0f0f23',
                pointBorderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#cbd5e1',
                        font: {
                            size: 11
                        }
                    },
                    grid: {
                        color: '#1e293b',
                        drawBorder: false
                    }
                },
                x: {
                    ticks: {
                        color: '#cbd5e1',
                        font: {
                            size: 11
                        }
                    },
                    grid: {
                        color: '#1e293b',
                        drawBorder: false
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(22, 33, 62, 0.95)',
                    titleColor: '#f8fafc',
                    bodyColor: '#cbd5e1',
                    borderColor: '#1e293b',
                    borderWidth: 1,
                    padding: 12
                }
            }
        }
    });
}

function generateColors(count) {
    const colors = [
        '#00d4ff', '#7c3aed', '#ef4444', '#f59e0b', '#10b981',
        '#ec4899', '#8b5cf6', '#06b6d4', '#f97316', '#84cc16'
    ];
    
    const result = [];
    for (let i = 0; i < count; i++) {
        result.push(colors[i % colors.length]);
    }
    return result;
}

