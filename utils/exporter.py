"""
Export functionality for threat data (CSV and PDF)
"""
import pandas as pd
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

class ThreatExporter:
    """Handles export of threat data to CSV and PDF formats"""
    
    def __init__(self):
        self.export_dir = Config.EXPORT_DIR
    
    def export_to_csv(self, threats, filename=None):
        """
        Export threats to CSV file
        
        Args:
            threats (list): List of threat dictionaries
            filename (str): Optional filename
        
        Returns:
            str: Path to exported CSV file
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'threats_export_{timestamp}.csv'
        
        filepath = os.path.join(self.export_dir, filename)
        
        # Prepare data for DataFrame
        data = []
        for threat in threats:
            # Convert MongoDB ObjectId to string if present
            threat_id = str(threat.get('_id', ''))
            row = {
                'ID': threat_id,
                'IP': threat.get('ip', ''),
                'Domain': threat.get('domain', ''),
                'Type': threat.get('type', ''),
                'Threat Score': threat.get('threat_score', 0),
                'Confidence': threat.get('confidence', 0),
                'Country': threat.get('country', 'Unknown'),
                'Tags': ', '.join(threat.get('tags', [])),
                'Created At': threat.get('created_at', ''),
                'Updated At': threat.get('updated_at', '')
            }
            data.append(row)
        
        # Create DataFrame and export
        df = pd.DataFrame(data)
        df.to_csv(filepath, index=False)
        
        return filepath
    
    def export_to_pdf(self, threats, filename=None):
        """
        Export threats to PDF file
        
        Args:
            threats (list): List of threat dictionaries
            filename (str): Optional filename
        
        Returns:
            str: Path to exported PDF file
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'threats_export_{timestamp}.pdf'
        
        filepath = os.path.join(self.export_dir, filename)
        
        # Create PDF document
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []
        
        # Define styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12
        )
        
        # Add title
        story.append(Paragraph("Cyber Threat Intelligence Report", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Add metadata
        metadata = [
            ['Generated At:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ['Total Threats:', str(len(threats))],
        ]
        metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(metadata_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Add threats table
        if threats:
            story.append(Paragraph("Threat Details", heading_style))
            
            # Prepare table data
            table_data = [['IP/Domain', 'Type', 'Score', 'Confidence', 'Country', 'Tags']]
            
            for threat in threats[:100]:  # Limit to 100 for PDF
                ip_or_domain = threat.get('ip', '') or threat.get('domain', 'N/A')
                threat_type = threat.get('type', 'unknown')
                score = str(threat.get('threat_score', 0))
                confidence = str(threat.get('confidence', 0))
                country = threat.get('country', 'Unknown')
                tags = ', '.join(threat.get('tags', [])[:3])  # Limit tags
                
                table_data.append([ip_or_domain, threat_type, score, confidence, country, tags])
            
            # Create table
            threat_table = Table(table_data, colWidths=[1.5*inch, 0.8*inch, 0.6*inch, 0.8*inch, 0.8*inch, 1.5*inch])
            threat_table.setStyle(TableStyle([
                # Header row
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                # Data rows
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ]))
            
            story.append(threat_table)
        else:
            story.append(Paragraph("No threats found.", styles['Normal']))
        
        # Build PDF
        doc.build(story)
        
        return filepath
    
    def get_export_file_path(self, filename):
        """Get full path for export file"""
        return os.path.join(self.export_dir, filename)

