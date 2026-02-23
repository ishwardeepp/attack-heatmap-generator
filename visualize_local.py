"""
Local Heatmap Visualizer for MITRE ATT&CK
Generates beautiful HTML/SVG heatmaps locally without needing Navigator.
"""

import json
from typing import Dict, List, Tuple
from pathlib import Path


# MITRE ATT&CK Tactics in order
TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "short": "Recon"},
    {"id": "TA0042", "name": "Resource Development", "short": "Resource Dev"},
    {"id": "TA0001", "name": "Initial Access", "short": "Initial Access"},
    {"id": "TA0002", "name": "Execution", "short": "Execution"},
    {"id": "TA0003", "name": "Persistence", "short": "Persistence"},
    {"id": "TA0004", "name": "Privilege Escalation", "short": "Priv Esc"},
    {"id": "TA0005", "name": "Defense Evasion", "short": "Defense Evasion"},
    {"id": "TA0006", "name": "Credential Access", "short": "Cred Access"},
    {"id": "TA0007", "name": "Discovery", "short": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement", "short": "Lateral Move"},
    {"id": "TA0009", "name": "Collection", "short": "Collection"},
    {"id": "TA0011", "name": "Command and Control", "short": "C2"},
    {"id": "TA0010", "name": "Exfiltration", "short": "Exfiltration"},
    {"id": "TA0040", "name": "Impact", "short": "Impact"},
]


def get_color_for_score(score: float, min_score: float, max_score: float) -> str:
    """
    Get color based on score using gradient from red (low) to yellow to green (high).
    
    Args:
        score: Technique score
        min_score: Minimum score in dataset
        max_score: Maximum score in dataset
        
    Returns:
        RGB color string
    """
    if max_score == min_score:
        return "rgb(255, 255, 102)"  # Yellow if all same
    
    # Normalize score to 0-1
    normalized = (score - min_score) / (max_score - min_score)
    
    if normalized < 0.5:
        # Red to Yellow (low to medium)
        ratio = normalized * 2
        r = 255
        g = int(102 + (153 * ratio))  # 102 (red-ish) to 255 (yellow)
        b = int(102 * (1 - ratio))     # 102 to 0
    else:
        # Yellow to Green (medium to high)
        ratio = (normalized - 0.5) * 2
        r = int(255 * (1 - ratio))     # 255 to 102
        g = 255
        b = int(102 * ratio)           # 0 to 102
    
    return f"rgb({r}, {g}, {b})"


def generate_html_heatmap(
    navigator_json_path: str,
    output_html_path: str,
    title: str = "MITRE ATT&CK Heatmap"
) -> str:
    """
    Generate an interactive HTML heatmap from Navigator JSON.
    
    Args:
        navigator_json_path: Path to Navigator layer JSON
        output_html_path: Where to save the HTML file
        title: Title for the heatmap
        
    Returns:
        Path to generated HTML file
    """
    # Load the Navigator JSON
    with open(navigator_json_path, 'r') as f:
        layer_data = json.load(f)
    
    # Extract techniques and scores
    techniques = {}
    for tech in layer_data.get('techniques', []):
        tech_id = tech.get('techniqueID')
        score = tech.get('score', 0)
        comment = tech.get('comment', '')
        techniques[tech_id] = {'score': score, 'comment': comment}
    
    # Get score range
    scores = [t['score'] for t in techniques.values()]
    min_score = min(scores) if scores else 0
    max_score = max(scores) if scores else 1
    
    # Load full ATT&CK data to get technique details
    # For now, we'll use a simplified mapping
    # In production, this would load from the cached STIX data
    
    # Generate HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .stats {{
            display: flex;
            justify-content: space-around;
            padding: 20px;
            background: #f8f9fa;
            border-bottom: 2px solid #dee2e6;
        }}
        
        .stat-box {{
            text-align: center;
            padding: 15px;
        }}
        
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        
        .stat-label {{
            color: #6c757d;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        
        .legend {{
            padding: 20px;
            background: #f8f9fa;
            border-bottom: 2px solid #dee2e6;
        }}
        
        .legend-title {{
            font-weight: bold;
            margin-bottom: 10px;
            color: #333;
        }}
        
        .legend-gradient {{
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .gradient-bar {{
            flex: 1;
            height: 30px;
            background: linear-gradient(to right, 
                rgb(255, 102, 102), 
                rgb(255, 255, 102), 
                rgb(102, 255, 102));
            border-radius: 5px;
            border: 1px solid #ddd;
        }}
        
        .legend-labels {{
            display: flex;
            justify-content: space-between;
            font-size: 0.9em;
            color: #6c757d;
            margin-top: 5px;
        }}
        
        .heatmap {{
            padding: 20px;
            overflow-x: auto;
        }}
        
        .technique-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 10px;
            margin-top: 20px;
        }}
        
        .tactic-section {{
            margin-bottom: 30px;
        }}
        
        .tactic-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            border-radius: 8px;
            font-weight: bold;
            font-size: 1.1em;
            margin-bottom: 15px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .technique-card {{
            background: white;
            border: 2px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            transition: all 0.3s ease;
            cursor: pointer;
            position: relative;
            overflow: hidden;
        }}
        
        .technique-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 16px rgba(0,0,0,0.2);
            border-color: #667eea;
        }}
        
        .technique-id {{
            font-weight: bold;
            font-size: 1.1em;
            margin-bottom: 5px;
        }}
        
        .technique-score {{
            font-size: 0.9em;
            color: #6c757d;
            margin-top: 5px;
        }}
        
        .score-badge {{
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(0,0,0,0.7);
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        
        .no-techniques {{
            text-align: center;
            color: #6c757d;
            padding: 40px;
            font-style: italic;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
            border-top: 2px solid #dee2e6;
        }}
        
        @media print {{
            body {{
                background: white;
            }}
            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{title}</h1>
            <p>Interactive MITRE ATT&CK Technique Heatmap</p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">{len(techniques)}</div>
                <div class="stat-label">Total Techniques</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{min_score:.1f}</div>
                <div class="stat-label">Min Score</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{max_score:.1f}</div>
                <div class="stat-label">Max Score</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{sum(scores)/len(scores) if scores else 0:.1f}</div>
                <div class="stat-label">Avg Score</div>
            </div>
        </div>
        
        <div class="legend">
            <div class="legend-title">Score Intensity</div>
            <div class="legend-gradient">
                <span>Low</span>
                <div class="gradient-bar"></div>
                <span>High</span>
            </div>
            <div class="legend-labels">
                <span>Least Common</span>
                <span>Most Common</span>
            </div>
        </div>
        
        <div class="heatmap">
"""
    
    # Group techniques by tactic (simplified - showing all in one list for now)
    html += f"""
            <div class="tactic-section">
                <div class="tactic-header">Your Techniques</div>
                <div class="technique-grid">
"""
    
    # Sort techniques by ID
    sorted_techniques = sorted(techniques.items())
    
    for tech_id, tech_data in sorted_techniques:
        score = tech_data['score']
        color = get_color_for_score(score, min_score, max_score)
        
        html += f"""
                    <div class="technique-card" style="background-color: {color}; border-color: {color};">
                        <div class="technique-id">{tech_id}</div>
                        <div class="technique-score">Score: {score:.1f}</div>
                        <div class="score-badge">{score:.0f}</div>
                    </div>
"""
    
    html += """
                </div>
            </div>
        </div>
        
        <div class="footer">
            Generated by MITRE ATT&CK Heatmap Generator Pro<br>
            Techniques colored by frequency/score - Hover for details
        </div>
    </div>
    
    <script>
        // Add tooltips and interactivity
        document.querySelectorAll('.technique-card').forEach(card => {
            card.addEventListener('click', function() {
                const techId = this.querySelector('.technique-id').textContent;
                const url = `https://attack.mitre.org/techniques/${techId.replace('.', '/')}/`;
                window.open(url, '_blank');
            });
        });
        
        // Print functionality
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 'p') {
                window.print();
            }
        });
    </script>
</body>
</html>
"""
    
    # Save HTML file
    output_path = Path(output_html_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    return str(output_path)


def generate_svg_heatmap(
    navigator_json_path: str,
    output_svg_path: str,
    title: str = "MITRE ATT&CK Heatmap"
) -> str:
    """
    Generate a Navigator-style SVG heatmap organized by tactics.
    
    Args:
        navigator_json_path: Path to Navigator layer JSON
        output_svg_path: Where to save the SVG file
        title: Title for the heatmap
        
    Returns:
        Path to generated SVG file
    """
    from collections import defaultdict
    
    # Load the Navigator JSON
    with open(navigator_json_path, 'r') as f:
        layer_data = json.load(f)
    
    # Extract techniques and scores
    techniques_data = {}
    for tech in layer_data.get('techniques', []):
        tech_id = tech.get('techniqueID')
        score = tech.get('score', 0)
        techniques_data[tech_id] = score
    
    # Mock technique-to-tactic mapping (in real version, we'd load from STIX data)
    # For now, we'll use a simplified mapping based on common patterns
    TECHNIQUE_TACTIC_MAP = {
        # Reconnaissance
        'T1595': 'Reconnaissance', 'T1592': 'Reconnaissance', 'T1589': 'Reconnaissance',
        'T1590': 'Reconnaissance', 'T1591': 'Reconnaissance', 'T1598': 'Reconnaissance',
        'T1597': 'Reconnaissance', 'T1596': 'Reconnaissance', 'T1593': 'Reconnaissance',
        
        # Initial Access
        'T1566': 'Initial Access', 'T1091': 'Initial Access', 'T1195': 'Initial Access',
        'T1199': 'Initial Access', 'T1200': 'Initial Access', 'T1078': 'Initial Access',
        'T1133': 'Initial Access', 'T1189': 'Initial Access', 'T1190': 'Initial Access',
        
        # Execution  
        'T1059': 'Execution', 'T1203': 'Execution', 'T1204': 'Execution',
        'T1106': 'Execution', 'T1129': 'Execution', 'T1203': 'Execution',
        'T1047': 'Execution', 'T1053': 'Execution', 'T1648': 'Execution',
        'T1609': 'Execution', 'T1610': 'Execution', 'T1218': 'Execution',
        
        # Persistence
        'T1098': 'Persistence', 'T1136': 'Persistence', 'T1543': 'Persistence',
        'T1546': 'Persistence', 'T1053': 'Persistence', 'T1037': 'Persistence',
        'T1505': 'Persistence', 'T1078': 'Persistence', 'T1542': 'Persistence',
        'T1137': 'Persistence', 'T1176': 'Persistence',
        
        # Defense Evasion
        'T1548': 'Defense Evasion', 'T1134': 'Defense Evasion', 'T1197': 'Defense Evasion',
        'T1140': 'Defense Evasion', 'T1070': 'Defense Evasion', 'T1202': 'Defense Evasion',
        'T1036': 'Defense Evasion', 'T1556': 'Defense Evasion', 'T1027': 'Defense Evasion',
        'T1055': 'Defense Evasion', 'T1218': 'Defense Evasion', 'T1112': 'Defense Evasion',
        'T1562': 'Defense Evasion', 'T1497': 'Defense Evasion', 'T1014': 'Defense Evasion',
        
        # Credential Access
        'T1110': 'Credential Access', 'T1555': 'Credential Access', 'T1212': 'Credential Access',
        'T1187': 'Credential Access', 'T1606': 'Credential Access', 'T1056': 'Credential Access',
        'T1556': 'Credential Access', 'T1111': 'Credential Access', 'T1003': 'Credential Access',
        'T1528': 'Credential Access', 'T1558': 'Credential Access',
        
        # Discovery
        'T1087': 'Discovery', 'T1010': 'Discovery', 'T1217': 'Discovery',
        'T1580': 'Discovery', 'T1538': 'Discovery', 'T1613': 'Discovery',
        'T1482': 'Discovery', 'T1083': 'Discovery', 'T1046': 'Discovery',
        'T1135': 'Discovery', 'T1040': 'Discovery', 'T1201': 'Discovery',
        'T1120': 'Discovery', 'T1069': 'Discovery', 'T1057': 'Discovery',
        'T1012': 'Discovery', 'T1018': 'Discovery', 'T1518': 'Discovery',
        'T1082': 'Discovery', 'T1614': 'Discovery', 'T1016': 'Discovery',
        'T1049': 'Discovery', 'T1033': 'Discovery',
        
        # Lateral Movement
        'T1210': 'Lateral Movement', 'T1534': 'Lateral Movement', 'T1570': 'Lateral Movement',
        'T1563': 'Lateral Movement', 'T1021': 'Lateral Movement', 'T1091': 'Lateral Movement',
        'T1080': 'Lateral Movement', 'T1550': 'Lateral Movement',
        
        # Collection
        'T1560': 'Collection', 'T1123': 'Collection', 'T1119': 'Collection',
        'T1115': 'Collection', 'T1530': 'Collection', 'T1602': 'Collection',
        'T1213': 'Collection', 'T1005': 'Collection', 'T1039': 'Collection',
        'T1025': 'Collection', 'T1074': 'Collection', 'T1114': 'Collection',
        'T1113': 'Collection', 'T1125': 'Collection',
        
        # Command and Control
        'T1071': 'Command and Control', 'T1092': 'Command and Control', 'T1132': 'Command and Control',
        'T1001': 'Command and Control', 'T1568': 'Command and Control', 'T1573': 'Command and Control',
        'T1008': 'Command and Control', 'T1105': 'Command and Control', 'T1104': 'Command and Control',
        'T1095': 'Command and Control', 'T1571': 'Command and Control', 'T1572': 'Command and Control',
        'T1090': 'Command and Control', 'T1219': 'Command and Control', 'T1205': 'Command and Control',
        'T1102': 'Command and Control',
        
        # Exfiltration
        'T1020': 'Exfiltration', 'T1030': 'Exfiltration', 'T1048': 'Exfiltration',
        'T1041': 'Exfiltration', 'T1011': 'Exfiltration', 'T1052': 'Exfiltration',
        'T1567': 'Exfiltration', 'T1029': 'Exfiltration', 'T1537': 'Exfiltration',
        
        # Impact
        'T1531': 'Impact', 'T1485': 'Impact', 'T1486': 'Impact',
        'T1565': 'Impact', 'T1491': 'Impact', 'T1561': 'Impact',
        'T1499': 'Impact', 'T1495': 'Impact', 'T1490': 'Impact',
        'T1498': 'Impact', 'T1496': 'Impact', 'T1489': 'Impact',
    }
    
    # Group techniques by tactic
    tactics_techniques = defaultdict(list)
    for tech_id, score in techniques_data.items():
        # Get parent technique ID for mapping
        parent_id = tech_id.split('.')[0]
        tactic = TECHNIQUE_TACTIC_MAP.get(parent_id, 'Other')
        tactics_techniques[tactic].append((tech_id, score))
    
    # Sort techniques within each tactic
    for tactic in tactics_techniques:
        tactics_techniques[tactic].sort()
    
    # Tactic order
    tactic_order = [
        'Reconnaissance', 'Initial Access', 'Execution', 'Persistence',
        'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
        'Collection', 'Command and Control', 'Exfiltration', 'Impact', 'Other'
    ]
    
    # Filter to only tactics that have techniques
    active_tactics = [t for t in tactic_order if t in tactics_techniques]
    
    # Calculate dimensions
    tactic_width = 180
    tech_height = 45
    header_height = 100
    tactic_header_height = 35
    padding = 20
    gap = 10
    
    # Find max techniques in any tactic
    max_techs = max(len(tactics_techniques[t]) for t in active_tactics) if active_tactics else 0
    
    width = len(active_tactics) * (tactic_width + gap) + 2 * padding
    height = header_height + tactic_header_height + (max_techs * (tech_height + 5)) + padding + 50
    
    # Get score range
    scores = list(techniques_data.values())
    min_score = min(scores) if scores else 0
    max_score = max(scores) if scores else 1
    
    # Start SVG
    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
    <defs>
        <linearGradient id="bgGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" style="stop-color:#1e3a5f;stop-opacity:1" />
            <stop offset="100%" style="stop-color:#2d4a6f;stop-opacity:1" />
        </linearGradient>
        
        <filter id="shadow">
            <feGaussianBlur in="SourceAlpha" stdDeviation="2"/>
            <feOffset dx="0" dy="1"/>
            <feComponentTransfer><feFuncA type="linear" slope="0.3"/></feComponentTransfer>
            <feMerge><feMergeNode/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
    </defs>
    
    <!-- Background -->
    <rect width="{width}" height="{height}" fill="url(#bgGradient)"/>
    
    <!-- Header -->
    <text x="{width/2}" y="40" 
          font-family="'Segoe UI', sans-serif" 
          font-size="28" 
          font-weight="600" 
          text-anchor="middle" 
          fill="white">{title}</text>
    <text x="{width/2}" y="68" 
          font-family="'Segoe UI', sans-serif" 
          font-size="13" 
          text-anchor="middle" 
          fill="#cbd5e0">MITRE ATT&amp;CK Technique Heatmap</text>
    
    <!-- Tactics and Techniques -->
'''
    
    # Draw each tactic column
    for idx, tactic in enumerate(active_tactics):
        x = padding + idx * (tactic_width + gap)
        y_start = header_height
        
        techs = tactics_techniques[tactic]
        
        # Tactic header
        svg += f'''
    <!-- {tactic} -->
    <rect x="{x}" y="{y_start}" 
          width="{tactic_width}" height="{tactic_header_height}" 
          fill="#2d3748" rx="4" stroke="#4a5568" stroke-width="1"/>
    <text x="{x + tactic_width/2}" y="{y_start + 14}" 
          font-family="'Segoe UI', sans-serif" 
          font-size="11" 
          font-weight="600" 
          text-anchor="middle" 
          fill="#a0aec0">{tactic.upper()}</text>
    <text x="{x + tactic_width/2}" y="{y_start + 28}" 
          font-family="'Segoe UI', sans-serif" 
          font-size="10" 
          text-anchor="middle" 
          fill="#718096">{len(techs)} Technique{'s' if len(techs) != 1 else ''}</text>
'''
        
        # Draw techniques
        for tech_idx, (tech_id, score) in enumerate(techs):
            tech_y = y_start + tactic_header_height + 5 + tech_idx * (tech_height + 5)
            
            # Get color
            color = get_color_for_score(score, min_score, max_score)
            
            # Check if sub-technique
            is_sub = '.' in tech_id
            
            svg += f'''
    <g>
        <rect x="{x}" y="{tech_y}" 
              width="{tactic_width}" height="{tech_height}" 
              fill="{color}" 
              stroke="{'#4a5568' if is_sub else '#2d3748'}" 
              stroke-width="{'1' if is_sub else '2'}" 
              rx="4" 
              filter="url(#shadow)"/>
        
        {'<circle cx="' + str(x + 8) + '" cy="' + str(tech_y + 8) + '" r="3" fill="#3182ce"/>' if is_sub else ''}
        
        <text x="{x + 10}" y="{tech_y + 20}" 
              font-family="'SF Mono', 'Consolas', monospace" 
              font-size="12" 
              font-weight="600" 
              fill="#1a202c">{tech_id}</text>
        
        <rect x="{x + tactic_width - 30}" y="{tech_y + 8}" 
              width="22" height="16" 
              fill="rgba(0,0,0,0.7)" rx="3"/>
        <text x="{x + tactic_width - 19}" y="{tech_y + 19}" 
              font-family="'Segoe UI', sans-serif" 
              font-size="10" 
              font-weight="700" 
              text-anchor="middle" 
              fill="white">{score:.0f}</text>
    </g>
'''
    
    svg += f'''
    <!-- Footer -->
    <text x="{width/2}" y="{height - 20}" 
          font-family="'Segoe UI', sans-serif" 
          font-size="10" 
          text-anchor="middle" 
          fill="#718096">Generated by MITRE ATT&amp;CK Heatmap Generator  •  
          <tspan fill="#cbd5e0">●</tspan> Parent  
          <tspan fill="#3182ce" dx="5">●</tspan> Sub-technique</text>
</svg>'''
    
    # Save SVG
    output_path = Path(output_svg_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(svg)
    
    return str(output_path)
    """
    Generate a clean, professional, blog-ready SVG heatmap.
    
    Args:
        navigator_json_path: Path to Navigator layer JSON
        output_svg_path: Where to save the SVG file
        title: Title for the heatmap
        
    Returns:
        Path to generated SVG file
    """
    # Load the Navigator JSON
    with open(navigator_json_path, 'r') as f:
        layer_data = json.load(f)
    
    # Extract techniques and scores
    techniques = {}
    for tech in layer_data.get('techniques', []):
        tech_id = tech.get('techniqueID')
        score = tech.get('score', 0)
        techniques[tech_id] = score
    
    # Get score range
    scores = list(techniques.values())
    min_score = min(scores) if scores else 0
    max_score = max(scores) if scores else 1
    avg_score = sum(scores) / len(scores) if scores else 0
    
    # Calculate optimal layout
    total_techs = len(techniques)
    
    # Determine grid size based on number of techniques
    if total_techs <= 20:
        techniques_per_row = 10
    elif total_techs <= 50:
        techniques_per_row = 12
    else:
        techniques_per_row = 15
    
    rows = (total_techs + techniques_per_row - 1) // techniques_per_row
    
    # Dimensions
    cell_size = 65
    cell_gap = 6
    padding = 40
    header_height = 120
    stats_height = 80
    legend_height = 70
    footer_height = 50
    
    grid_width = (techniques_per_row * cell_size) + ((techniques_per_row - 1) * cell_gap)
    content_width = max(grid_width, 800)  # Minimum width
    
    width = content_width + (2 * padding)
    height = header_height + stats_height + legend_height + (rows * (cell_size + cell_gap)) + footer_height + (2 * padding)
    
    # Sort techniques by ID
    sorted_techniques = sorted(techniques.items())
    
    # Count parent vs sub-techniques
    parent_count = sum(1 for t in techniques if '.' not in t)
    sub_count = total_techs - parent_count
    
    # Start SVG with clean, modern design
    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <defs>
        <!-- Gradient background -->
        <linearGradient id="bgGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:#667eea;stop-opacity:1" />
            <stop offset="100%" style="stop-color:#764ba2;stop-opacity:1" />
        </linearGradient>
        
        <!-- Score gradient -->
        <linearGradient id="scoreGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" style="stop-color:#ff6b6b;stop-opacity:1" />
            <stop offset="50%" style="stop-color:#ffd93d;stop-opacity:1" />
            <stop offset="100%" style="stop-color:#6bcf7f;stop-opacity:1" />
        </linearGradient>
        
        <!-- Card shadow -->
        <filter id="cardShadow">
            <feGaussianBlur in="SourceAlpha" stdDeviation="2"/>
            <feOffset dx="0" dy="2" result="offsetblur"/>
            <feComponentTransfer>
                <feFuncA type="linear" slope="0.15"/>
            </feComponentTransfer>
            <feMerge>
                <feMergeNode/>
                <feMergeNode in="SourceGraphic"/>
            </feMerge>
        </filter>
        
        <!-- Subtle glow for cards -->
        <filter id="glow">
            <feGaussianBlur stdDeviation="1.5" result="coloredBlur"/>
            <feMerge>
                <feMergeNode in="coloredBlur"/>
                <feMergeNode in="SourceGraphic"/>
            </feMerge>
        </filter>
    </defs>
    
    <!-- Background -->
    <rect width="{width}" height="{height}" fill="url(#bgGradient)"/>
    
    <!-- Main container -->
    <rect x="{padding/2}" y="{padding/2}" 
          width="{width - padding}" height="{height - padding}" 
          fill="white" rx="12" opacity="0.98"/>
    
    <!-- Header -->
    <text x="{width/2}" y="{padding + 35}" 
          font-family="'Segoe UI', -apple-system, system-ui, sans-serif" 
          font-size="36" 
          font-weight="700" 
          text-anchor="middle" 
          fill="#2d3748">{title}</text>
    
    <text x="{width/2}" y="{padding + 62}" 
          font-family="'Segoe UI', -apple-system, system-ui, sans-serif" 
          font-size="15" 
          text-anchor="middle" 
          fill="#718096">MITRE ATT&amp;CK Technique Coverage Analysis</text>
    
    <!-- Divider -->
    <line x1="{padding + 40}" y1="{padding + 80}" 
          x2="{width - padding - 40}" y2="{padding + 80}" 
          stroke="#e2e8f0" stroke-width="1"/>
    
    <!-- Statistics Section -->
    <g id="stats" transform="translate(0, {padding + 95})">
        <!-- Stats container -->
        <rect x="{padding + 30}" y="0" 
              width="{width - 2*padding - 60}" height="{stats_height}" 
              fill="#f7fafc" rx="8" stroke="#e2e8f0" stroke-width="1"/>
        
        <!-- Calculate positions for 4 stats -->
        {f'''
        <!-- Total -->
        <g transform="translate({padding + (width - 2*padding) * 0.15}, 20)">
            <text x="0" y="0" 
                  font-family="'Segoe UI', sans-serif" 
                  font-size="11" 
                  font-weight="600" 
                  text-anchor="middle" 
                  fill="#718096" 
                  letter-spacing="1">TOTAL</text>
            <text x="0" y="30" 
                  font-family="'Segoe UI', sans-serif" 
                  font-size="32" 
                  font-weight="700" 
                  text-anchor="middle" 
                  fill="#667eea">{total_techs}</text>
        </g>
        
        <!-- Min -->
        <g transform="translate({padding + (width - 2*padding) * 0.38}, 20)">
            <text x="0" y="0" 
                  font-family="'Segoe UI', sans-serif" 
                  font-size="11" 
                  font-weight="600" 
                  text-anchor="middle" 
                  fill="#718096" 
                  letter-spacing="1">MIN</text>
            <text x="0" y="30" 
                  font-family="'Segoe UI', sans-serif" 
                  font-size="32" 
                  font-weight="700" 
                  text-anchor="middle" 
                  fill="#fc8181">{min_score:.1f}</text>
        </g>
        
        <!-- Avg -->
        <g transform="translate({padding + (width - 2*padding) * 0.62}, 20)">
            <text x="0" y="0" 
                  font-family="'Segoe UI', sans-serif" 
                  font-size="11" 
                  font-weight="600" 
                  text-anchor="middle" 
                  fill="#718096" 
                  letter-spacing="1">AVG</text>
            <text x="0" y="30" 
                  font-family="'Segoe UI', sans-serif" 
                  font-size="32" 
                  font-weight="700" 
                  text-anchor="middle" 
                  fill="#f6ad55">{avg_score:.1f}</text>
        </g>
        
        <!-- Max -->
        <g transform="translate({padding + (width - 2*padding) * 0.85}, 20)">
            <text x="0" y="0" 
                  font-family="'Segoe UI', sans-serif" 
                  font-size="11" 
                  font-weight="600" 
                  text-anchor="middle" 
                  fill="#718096" 
                  letter-spacing="1">MAX</text>
            <text x="0" y="30" 
                  font-family="'Segoe UI', sans-serif" 
                  font-size="32" 
                  font-weight="700" 
                  text-anchor="middle" 
                  fill="#68d391">{max_score:.1f}</text>
        </g>
        '''}
    </g>
    
    <!-- Legend Section -->
    <g id="legend" transform="translate(0, {padding + 95 + stats_height + 15})">
        <text x="{padding + 30}" y="15" 
              font-family="'Segoe UI', sans-serif" 
              font-size="13" 
              font-weight="600" 
              fill="#2d3748">Score Intensity</text>
        
        <!-- Gradient bar -->
        <rect x="{padding + 30}" y="25" 
              width="{width - 2*padding - 200}" height="20" 
              fill="url(#scoreGradient)" 
              rx="10"/>
        
        <!-- Labels -->
        <text x="{padding + 30}" y="58" 
              font-family="'Segoe UI', sans-serif" 
              font-size="11" 
              fill="#718096">Low Frequency</text>
        <text x="{width - padding - 200}" y="58" 
              font-family="'Segoe UI', sans-serif" 
              font-size="11" 
              fill="#718096" 
              text-anchor="end">High Frequency</text>
    </g>
    
    <!-- Techniques Grid -->
    <g id="techniques" transform="translate({padding + (content_width - grid_width)/2}, {padding + header_height + stats_height + legend_height})">
'''
    
    # Draw technique cells with improved styling
    for idx, (tech_id, score) in enumerate(sorted_techniques):
        row = idx // techniques_per_row
        col = idx % techniques_per_row
        
        x = col * (cell_size + cell_gap)
        y = row * (cell_size + cell_gap)
        
        # Get color
        color = get_color_for_score(score, min_score, max_score)
        
        # Check if sub-technique
        is_sub = '.' in tech_id
        
        # Darker border for parent, lighter for sub
        border_color = '#2d3748' if not is_sub else '#718096'
        border_width = '2' if not is_sub else '1.5'
        
        svg += f'''
        <g class="tech-card">
            <!-- Card -->
            <rect x="{x}" y="{y}" 
                  width="{cell_size}" height="{cell_size}" 
                  fill="{color}" 
                  stroke="{border_color}" 
                  stroke-width="{border_width}" 
                  rx="6" 
                  filter="url(#cardShadow)"/>
            
            <!-- Technique ID -->
            <text x="{x + cell_size/2}" y="{y + cell_size/2 - 2}" 
                  font-family="'SF Mono', 'Consolas', 'Monaco', monospace" 
                  font-size="11" 
                  font-weight="600" 
                  text-anchor="middle" 
                  fill="#1a202c">{tech_id}</text>
            
            <!-- Score badge -->
            <g transform="translate({x + cell_size - 24}, {y + 6})">
                <rect x="0" y="0" width="18" height="14" 
                      fill="rgba(0,0,0,0.75)" rx="3"/>
                <text x="9" y="10" 
                      font-family="'Segoe UI', sans-serif" 
                      font-size="9" 
                      font-weight="700" 
                      text-anchor="middle" 
                      fill="white">{score:.0f}</text>
            </g>
            
            <!-- Sub-technique indicator dot -->
            {f'<circle cx="{x + 8}" cy="{y + 8}" r="3" fill="#3182ce"/>' if is_sub else ''}
        </g>
'''
    
    svg += f'''
    </g>
    
    <!-- Footer -->
    <g id="footer" transform="translate(0, {height - footer_height - 10})">
        <text x="{width/2}" y="15" 
              font-family="'Segoe UI', sans-serif" 
              font-size="11" 
              text-anchor="middle" 
              fill="#a0aec0">Generated by MITRE ATT&amp;CK Heatmap Generator</text>
        
        <!-- Legend indicators -->
        <g transform="translate({width/2 - 80}, 25)">
            <rect x="0" y="0" width="14" height="14" 
                  fill="#e2e8f0" stroke="#2d3748" stroke-width="2" rx="3"/>
            <text x="20" y="11" 
                  font-family="'Segoe UI', sans-serif" 
                  font-size="10" 
                  fill="#718096">Parent Technique</text>
            
            <circle cx="90" cy="7" r="3" fill="#3182ce"/>
            <rect x="84" y="0" width="14" height="14" 
                  fill="#e2e8f0" stroke="#718096" stroke-width="1.5" rx="3"/>
            <text x="104" y="11" 
                  font-family="'Segoe UI', sans-serif" 
                  font-size="10" 
                  fill="#718096">Sub-technique</text>
        </g>
    </g>
    
</svg>'''
    
    # Save SVG file
    output_path = Path(output_svg_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(svg)
    
    return str(output_path)
    """
    Generate a professional, blog-ready SVG heatmap.
    
    Args:
        navigator_json_path: Path to Navigator layer JSON
        output_svg_path: Where to save the SVG file
        title: Title for the heatmap
        
    Returns:
        Path to generated SVG file
    """
    # Load the Navigator JSON
    with open(navigator_json_path, 'r') as f:
        layer_data = json.load(f)
    
    # Extract techniques and scores
    techniques = {}
    for tech in layer_data.get('techniques', []):
        tech_id = tech.get('techniqueID')
        score = tech.get('score', 0)
        techniques[tech_id] = score
    
    # Get score range
    scores = list(techniques.values())
    min_score = min(scores) if scores else 0
    max_score = max(scores) if scores else 1
    avg_score = sum(scores) / len(scores) if scores else 0
    
    # Calculate SVG dimensions for a professional layout
    techniques_per_row = 12
    rows = (len(techniques) + techniques_per_row - 1) // techniques_per_row
    cell_size = 70
    cell_gap = 8
    padding = 50
    header_height = 140
    legend_height = 80
    footer_height = 40
    stats_height = 60
    
    width = (techniques_per_row * (cell_size + cell_gap)) + (2 * padding)
    height = (rows * (cell_size + cell_gap)) + header_height + legend_height + stats_height + footer_height + (2 * padding)
    
    # Sort techniques by ID
    sorted_techniques = sorted(techniques.items())
    
    # Start SVG with modern styling
    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <!-- Definitions for gradients, shadows, and patterns -->
    <defs>
        <!-- Background gradient -->
        <linearGradient id="bgGradient" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" style="stop-color:#667eea;stop-opacity:1" />
            <stop offset="100%" style="stop-color:#764ba2;stop-opacity:1" />
        </linearGradient>
        
        <!-- Score gradient for legend -->
        <linearGradient id="scoreGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" style="stop-color:rgb(255,102,102);stop-opacity:1" />
            <stop offset="50%" style="stop-color:rgb(255,255,102);stop-opacity:1" />
            <stop offset="100%" style="stop-color:rgb(102,255,102);stop-opacity:1" />
        </linearGradient>
        
        <!-- Drop shadow filter -->
        <filter id="dropShadow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur in="SourceAlpha" stdDeviation="3"/>
            <feOffset dx="0" dy="2" result="offsetblur"/>
            <feComponentTransfer>
                <feFuncA type="linear" slope="0.3"/>
            </feComponentTransfer>
            <feMerge>
                <feMergeNode/>
                <feMergeNode in="SourceGraphic"/>
            </feMerge>
        </filter>
        
        <!-- Card shadow -->
        <filter id="cardShadow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur in="SourceAlpha" stdDeviation="2"/>
            <feOffset dx="0" dy="1" result="offsetblur"/>
            <feComponentTransfer>
                <feFuncA type="linear" slope="0.2"/>
            </feComponentTransfer>
            <feMerge>
                <feMergeNode/>
                <feMergeNode in="SourceGraphic"/>
            </feMerge>
        </filter>
    </defs>
    
    <!-- Background -->
    <rect width="{width}" height="{height}" fill="url(#bgGradient)"/>
    
    <!-- Main content container -->
    <rect x="{padding/2}" y="{padding/2}" width="{width - padding}" height="{height - padding}" 
          fill="white" rx="15" filter="url(#dropShadow)"/>
    
    <!-- Header Section -->
    <g id="header">
        <!-- Title -->
        <text x="{width/2}" y="{padding + 40}" 
              font-family="'Segoe UI', Arial, sans-serif" 
              font-size="32" 
              font-weight="bold" 
              text-anchor="middle" 
              fill="#2c3e50">{title}</text>
        
        <!-- Subtitle -->
        <text x="{width/2}" y="{padding + 70}" 
              font-family="'Segoe UI', Arial, sans-serif" 
              font-size="16" 
              text-anchor="middle" 
              fill="#7f8c8d">MITRE ATT&amp;CK Technique Coverage Analysis</text>
        
        <!-- Decorative line -->
        <line x1="{padding + 100}" y1="{padding + 85}" 
              x2="{width - padding - 100}" y2="{padding + 85}" 
              stroke="#667eea" stroke-width="2" opacity="0.3"/>
    </g>
    
    <!-- Statistics Section -->
    <g id="stats" transform="translate(0, {padding + 90})">
        <!-- Stats background -->
        <rect x="{padding}" y="0" width="{width - 2*padding}" height="{stats_height}" 
              fill="#f8f9fa" rx="8" opacity="0.5"/>
        
        <!-- Total Techniques -->
        <text x="{padding + 30}" y="25" 
              font-family="'Segoe UI', Arial, sans-serif" 
              font-size="14" 
              font-weight="600" 
              fill="#667eea">TOTAL</text>
        <text x="{padding + 30}" y="45" 
              font-family="'Segoe UI', Arial, sans-serif" 
              font-size="22" 
              font-weight="bold" 
              fill="#2c3e50">{len(techniques)}</text>
        
        <!-- Min Score -->
        <text x="{width/2 - 150}" y="25" 
              font-family="'Segoe UI', Arial, sans-serif" 
              font-size="14" 
              font-weight="600" 
              fill="#e74c3c">MIN</text>
        <text x="{width/2 - 150}" y="45" 
              font-family="'Segoe UI', Arial, sans-serif" 
              font-size="22" 
              font-weight="bold" 
              fill="#2c3e50">{min_score:.1f}</text>
        
        <!-- Avg Score -->
        <text x="{width/2}" y="25" 
              font-family="'Segoe UI', Arial, sans-serif" 
              font-size="14" 
              font-weight="600" 
              fill="#f39c12" 
              text-anchor="middle">AVG</text>
        <text x="{width/2}" y="45" 
              font-family="'Segoe UI', Arial, sans-serif" 
              font-size="22" 
              font-weight="bold" 
              fill="#2c3e50" 
              text-anchor="middle">{avg_score:.1f}</text>
        
        <!-- Max Score -->
        <text x="{width/2 + 150}" y="25" 
              font-family="'Segoe UI', Arial, sans-serif" 
              font-size="14" 
              font-weight="600" 
              fill="#27ae60" 
              text-anchor="end">MAX</text>
        <text x="{width/2 + 150}" y="45" 
              font-family="'Segoe UI', Arial, sans-serif" 
              font-size="22" 
              font-weight="bold" 
              fill="#2c3e50" 
              text-anchor="end">{max_score:.1f}</text>
    </g>
    
    <!-- Legend Section -->
    <g id="legend" transform="translate(0, {padding + 90 + stats_height + 20})">
        <text x="{padding + 20}" y="15" 
              font-family="'Segoe UI', Arial, sans-serif" 
              font-size="14" 
              font-weight="600" 
              fill="#2c3e50">Score Intensity</text>
        
        <!-- Gradient bar -->
        <rect x="{padding + 20}" y="25" 
              width="{width - 2*padding - 200}" height="25" 
              fill="url(#scoreGradient)" 
              rx="4" 
              stroke="#dee2e6" 
              stroke-width="1"/>
        
        <!-- Legend labels -->
        <text x="{padding + 20}" y="60" 
              font-family="'Segoe UI', Arial, sans-serif" 
              font-size="12" 
              fill="#7f8c8d">Low Frequency</text>
        <text x="{width - padding - 180}" y="60" 
              font-family="'Segoe UI', Arial, sans-serif" 
              font-size="12" 
              fill="#7f8c8d" 
              text-anchor="end">High Frequency</text>
    </g>
    
    <!-- Techniques Grid -->
    <g id="techniques" transform="translate(0, {padding + header_height + stats_height + legend_height})">
'''
    
    # Draw technique cells
    for idx, (tech_id, score) in enumerate(sorted_techniques):
        row = idx // techniques_per_row
        col = idx % techniques_per_row
        
        x = padding + (col * (cell_size + cell_gap))
        y = (row * (cell_size + cell_gap))
        
        # Get color based on score
        color = get_color_for_score(score, min_score, max_score)
        
        # Determine if it's a sub-technique
        is_sub = '.' in tech_id
        
        svg += f'''
        <!-- {tech_id} -->
        <g class="technique-card" transform="translate({x}, {y})">
            <!-- Card background -->
            <rect x="0" y="0" width="{cell_size}" height="{cell_size}" 
                  fill="{color}" 
                  rx="6" 
                  stroke="{'#95a5a6' if is_sub else '#2c3e50'}" 
                  stroke-width="{'1.5' if is_sub else '2'}" 
                  filter="url(#cardShadow)"/>
            
            <!-- Technique ID -->
            <text x="{cell_size/2}" y="{cell_size/2 - 8}" 
                  font-family="'Consolas', 'Monaco', monospace" 
                  font-size="{'11' if is_sub else '12'}" 
                  font-weight="bold" 
                  text-anchor="middle" 
                  fill="#000" 
                  opacity="0.9">{tech_id}</text>
            
            <!-- Score badge -->
            <rect x="{cell_size - 26}" y="4" width="22" height="16" 
                  fill="rgba(0,0,0,0.7)" 
                  rx="3"/>
            <text x="{cell_size - 15}" y="15" 
                  font-family="'Segoe UI', Arial, sans-serif" 
                  font-size="10" 
                  font-weight="bold" 
                  text-anchor="middle" 
                  fill="white">{score:.0f}</text>
            
            <!-- Sub-technique indicator -->
            {'<circle cx="8" cy="8" r="3" fill="#3498db" opacity="0.7"/>' if is_sub else ''}
        </g>
'''
    
    svg += '''
    </g>
    
    <!-- Footer -->
    <g id="footer">
'''
    
    footer_y = height - footer_height
    
    svg += f'''
        <!-- Branding -->
        <text x="{width/2}" y="{footer_y + 20}" 
              font-family="'Segoe UI', Arial, sans-serif" 
              font-size="11" 
              text-anchor="middle" 
              fill="#95a5a6">Generated by MITRE ATT&amp;CK Heatmap Generator</text>
        
        <!-- Attribution -->
        <text x="{width/2}" y="{footer_y + 35}" 
              font-family="'Segoe UI', Arial, sans-serif" 
              font-size="10" 
              text-anchor="middle" 
              fill="#bdc3c7">
            <tspan fill="#667eea">●</tspan> Parent Technique  
            <tspan fill="#3498db" dx="20">●</tspan> Sub-technique
        </text>
    </g>
'''
    
    svg += '''
</svg>'''
    
    # Save SVG file
    output_path = Path(output_svg_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(svg)
    
    return str(output_path)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python visualize_local.py <navigator_json_file>")
        print("Example: python visualize_local.py output/my_analysis.json")
        sys.exit(1)
    
    input_file = sys.argv[1]
    base_name = Path(input_file).stem
    
    # Generate both HTML and SVG
    html_path = f"output/{base_name}_heatmap.html"
    svg_path = f"output/{base_name}_heatmap.svg"
    
    print(f"Generating visualizations from: {input_file}")
    print()
    
    # Generate HTML
    try:
        html_output = generate_html_heatmap(input_file, html_path)
        print(f"✓ Interactive HTML heatmap: {html_output}")
        print(f"  Open in browser to view!")
    except Exception as e:
        print(f"✗ Error generating HTML: {e}")
    
    # Generate SVG
    try:
        svg_output = generate_svg_heatmap(input_file, svg_path)
        print(f"✓ SVG heatmap: {svg_output}")
        print(f"  Can be opened in browser or image editor")
    except Exception as e:
        print(f"✗ Error generating SVG: {e}")
    
    print()
    print("Done! Your heatmaps are ready to view locally.")