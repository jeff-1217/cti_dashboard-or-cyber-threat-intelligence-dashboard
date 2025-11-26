// Export JavaScript for CTI Dashboard

document.addEventListener('DOMContentLoaded', function() {
    const csvBtn = document.getElementById('export-csv-btn');
    const pdfBtn = document.getElementById('export-pdf-btn');
    
    csvBtn.addEventListener('click', handleCSVExport);
    pdfBtn.addEventListener('click', handlePDFExport);
});

async function handleCSVExport() {
    const limit = document.getElementById('export-limit').value;
    
    try {
        const response = await fetch('/api/export/csv', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ limit: parseInt(limit) })
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `threats_export_${new Date().toISOString().split('T')[0]}.csv`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } else {
            const error = await response.json();
            alert('Error exporting CSV: ' + (error.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('CSV export error:', error);
        alert('Error exporting CSV: ' + error.message);
    }
}

async function handlePDFExport() {
    const limit = document.getElementById('export-limit').value;
    
    try {
        const response = await fetch('/api/export/pdf', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ limit: parseInt(limit) })
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `threats_export_${new Date().toISOString().split('T')[0]}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } else {
            const error = await response.json();
            alert('Error exporting PDF: ' + (error.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('PDF export error:', error);
        alert('Error exporting PDF: ' + error.message);
    }
}

