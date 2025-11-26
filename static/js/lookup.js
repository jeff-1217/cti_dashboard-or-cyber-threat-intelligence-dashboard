// Lookup JavaScript for CTI Dashboard

let currentQuery = '';

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('lookup-form');
    const addTagBtn = document.getElementById('add-tag-btn');
    
    form.addEventListener('submit', handleLookup);
    addTagBtn.addEventListener('click', handleAddTag);
});

async function handleLookup(e) {
    e.preventDefault();
    
    const query = document.getElementById('query').value.trim();
    if (!query) {
        alert('Please enter an IP address or domain');
        return;
    }
    
    currentQuery = query;
    
    // Show loading state
    const spinner = document.getElementById('spinner');
    const lookupBtn = document.getElementById('lookup-btn');
    spinner.classList.remove('d-none');
    lookupBtn.disabled = true;
    
    // Hide previous results
    document.getElementById('results').classList.add('d-none');
    
    try {
        const response = await fetch('/api/lookup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ query: query })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            if (data.error) {
                showError('Error: ' + data.error);
            } else {
                displayResults(data);
            }
        } else {
            const errorMsg = data.error || `HTTP ${response.status}: ${response.statusText}`;
            showError(errorMsg);
        }
    } catch (error) {
        console.error('Lookup error:', error);
        showError('Network error: ' + error.message + '. Please check if the server is running.');
    } finally {
        spinner.classList.add('d-none');
        lookupBtn.disabled = false;
    }
}

function showError(message) {
    const resultsDiv = document.getElementById('results');
    resultsDiv.classList.remove('d-none');
    
    // Clear previous results
    document.getElementById('status-alert').innerHTML = `<strong>Error:</strong> ${message}`;
    document.getElementById('status-alert').className = 'alert alert-danger';
    document.getElementById('threat-score').textContent = 'N/A';
    document.getElementById('confidence').textContent = 'N/A';
    document.getElementById('country').textContent = 'Unknown';
    document.getElementById('tags').innerHTML = '<span class="text-muted">None</span>';
    document.getElementById('vt-results').innerHTML = '<p class="text-muted">No data available</p>';
    document.getElementById('abuse-results').innerHTML = '<p class="text-muted">No data available</p>';
}

function displayResults(data) {
    const resultsDiv = document.getElementById('results');
    resultsDiv.classList.remove('d-none');
    
    // Update status
    const statusText = document.getElementById('status-text');
    const statusAlert = document.getElementById('status-alert');
    
    let statusClass = 'alert-info';
    if (data.status === 'malicious') {
        statusClass = 'alert-danger';
        statusText.textContent = 'MALICIOUS';
    } else if (data.status === 'suspicious') {
        statusClass = 'alert-warning';
        statusText.textContent = 'SUSPICIOUS';
    } else {
        statusClass = 'alert-success';
        statusText.textContent = 'CLEAN';
    }
    
    statusAlert.className = `alert ${statusClass}`;
    
    // Update metrics
    document.getElementById('threat-score').textContent = data.threat_score || 0;
    document.getElementById('confidence').textContent = data.confidence || 0;
    document.getElementById('country').textContent = data.country || 'Unknown';
    
    // Update tags
    const tagsSpan = document.getElementById('tags');
    if (data.tags && data.tags.length > 0) {
        tagsSpan.innerHTML = data.tags.map(tag => 
            `<span class="badge bg-secondary me-1">${tag}</span>`
        ).join('');
    } else {
        tagsSpan.textContent = 'None';
    }
    
    // Display VirusTotal results
    displayVTResults(data.virustotal);
    
    // Display AbuseIPDB results
    displayAbuseResults(data.abuseipdb);
}

function displayVTResults(vtData) {
    const vtDiv = document.getElementById('vt-results');
    
    if (!vtData || vtData.error) {
        const errorMsg = vtData?.error || 'VirusTotal API key not configured or no data available';
        vtDiv.innerHTML = `<div class="alert alert-warning mb-0">${errorMsg}</div>`;
        return;
    }
    
    let html = '<div class="row text-light">';
    
    if (vtData.detection_count !== undefined) {
        html += `<div class="col-md-6 mb-3"><strong class="text-primary">Detections:</strong> <span class="text-light">${vtData.detection_count}</span></div>`;
    }
    
    if (vtData.total_scans !== undefined) {
        html += `<div class="col-md-6 mb-3"><strong class="text-primary">Total Scans:</strong> <span class="text-light">${vtData.total_scans}</span></div>`;
    }
    
    if (vtData.country) {
        html += `<div class="col-md-6 mb-3"><strong class="text-primary">Country:</strong> <span class="text-light">${vtData.country}</span></div>`;
    }
    
    if (vtData.asn) {
        html += `<div class="col-md-6 mb-3"><strong class="text-primary">ASN:</strong> <span class="text-light">${vtData.asn}</span></div>`;
    }
    
    html += '</div>';
    
    if (vtData.tags && vtData.tags.length > 0) {
        html += `<div class="mt-3"><strong class="text-primary">Tags:</strong> `;
        html += vtData.tags.map(tag => `<span class="badge bg-info me-1">${tag}</span>`).join('');
        html += '</div>';
    }
    
    if (vtData.message) {
        html += `<p class="text-secondary mt-2">${vtData.message}</p>`;
    }
    
    vtDiv.innerHTML = html;
}

function displayAbuseResults(abuseData) {
    const abuseDiv = document.getElementById('abuse-results');
    
    if (!abuseData || abuseData.error) {
        const errorMsg = abuseData?.error || 'AbuseIPDB API key not configured or no data available';
        abuseDiv.innerHTML = `<div class="alert alert-warning mb-0">${errorMsg}</div>`;
        return;
    }
    
    let html = '<div class="row text-light">';
    
    if (abuseData.confidence !== undefined) {
        html += `<div class="col-md-6 mb-3"><strong class="text-primary">Abuse Confidence:</strong> <span class="text-light">${abuseData.confidence}%</span></div>`;
    }
    
    if (abuseData.total_reports !== undefined && abuseData.total_reports > 0) {
        html += `<div class="col-md-6 mb-3"><strong class="text-primary">Total Reports:</strong> <span class="text-light">${abuseData.total_reports}</span></div>`;
    }
    if (abuseData.num_reports !== undefined) {
        html += `<div class="col-md-6 mb-3"><strong class="text-primary">Recent Reports (90 days):</strong> <span class="text-light">${abuseData.num_reports}</span></div>`;
    }
    
    if (abuseData.country) {
        html += `<div class="col-md-6 mb-3"><strong class="text-primary">Country:</strong> <span class="text-light">${abuseData.country}</span></div>`;
    }
    
    if (abuseData.isp) {
        html += `<div class="col-md-6 mb-3"><strong class="text-primary">ISP:</strong> <span class="text-light">${abuseData.isp}</span></div>`;
    }
    
    if (abuseData.usage_type) {
        html += `<div class="col-md-6 mb-3"><strong class="text-primary">Usage Type:</strong> <span class="text-light">${abuseData.usage_type}</span></div>`;
    }
    
    if (abuseData.is_whitelisted !== undefined) {
        html += `<div class="col-md-6 mb-3"><strong class="text-primary">Whitelisted:</strong> <span class="text-light">${abuseData.is_whitelisted ? 'Yes' : 'No'}</span></div>`;
    }
    
    html += '</div>';
    
    if (abuseData.tags && abuseData.tags.length > 0) {
        html += `<div class="mt-3"><strong class="text-primary">Tags:</strong> `;
        html += abuseData.tags.map(tag => `<span class="badge bg-info me-1">${tag}</span>`).join('');
        html += '</div>';
    }
    
    abuseDiv.innerHTML = html;
}

async function handleAddTag() {
    const tagInput = document.getElementById('manual-tag');
    const tag = tagInput.value.trim();
    
    if (!tag || !currentQuery) {
        alert('Please enter a tag and perform a lookup first');
        return;
    }
    
    try {
        const response = await fetch('/api/tag', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                query: currentQuery,
                tag: tag
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Update tags display
            const tagsSpan = document.getElementById('tags');
            tagsSpan.innerHTML = data.tags.map(t => 
                `<span class="badge bg-secondary me-1">${t}</span>`
            ).join('');
            
            tagInput.value = '';
            alert('Tag added successfully!');
        } else {
            alert('Error: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Add tag error:', error);
        alert('Error adding tag: ' + error.message);
    }
}

