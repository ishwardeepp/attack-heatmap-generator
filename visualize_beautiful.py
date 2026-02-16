"""
Beautiful Local Heatmap Visualizer for MITRE ATT&CK - REDESIGNED
Generates stunning, professional HTML/SVG heatmaps locally.
"""

import json
from typing import Dict, List
from pathlib import Path


def get_color_for_score(score: float, min_score: float, max_score: float) -> str:
    """Get vibrant color based on score."""
    if max_score == min_score:
        return "#3b82f6"
    
    normalized = (score - min_score) / (max_score - min_score)
    
    # Use a better color palette
    if normalized < 0.33:
        # Low: Red to Orange
        ratio = normalized / 0.33
        return f"rgba(239, 68, 68, {0.6 + ratio * 0.4})"  # Red
    elif normalized < 0.67:
        # Medium: Orange to Yellow
        return f"rgba(245, 158, 11, {0.7})"  # Orange
    else:
        # High: Yellow to Green
        ratio = (normalized - 0.67) / 0.33
        return f"rgba(34, 197, 94, {0.6 + ratio * 0.4})"  # Green


def generate_beautiful_html(
    navigator_json_path: str,
    output_html_path: str,
    title: str = "MITRE ATT&CK Heatmap"
) -> str:
    """Generate a beautiful, modern HTML heatmap."""
    
    with open(navigator_json_path, 'r') as f:
        layer_data = json.load(f)
    
    techniques = {}
    for tech in layer_data.get('techniques', []):
        tech_id = tech.get('techniqueID')
        score = tech.get('score', 0)
        comment = tech.get('comment', '')
        techniques[tech_id] = {'score': score, 'comment': comment}
    
    scores = [t['score'] for t in techniques.values()]
    min_score = min(scores) if scores else 0
    max_score = max(scores) if scores else 1
    avg_score = sum(scores) / len(scores) if scores else 0
    
    # Build the beautiful HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            line-height: 1.6;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1800px;
            margin: 0 auto;
        }}
        
        .header {{
            background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 50%, #ec4899 100%);
            padding: 60px 48px;
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            width: 200%;
            height: 200%;
            top: -50%;
            left: -50%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 1px, transparent 1px);
            background-size: 50px 50px;
            animation: float 20s linear infinite;
        }}
        
        @keyframes float {{
            0% {{ transform: translate(0, 0); }}
            100% {{ transform: translate(50px, 50px); }}
        }}
        
        .header-content {{
            position: relative;
            z-index: 1;
        }}
        
        .header h1 {{
            font-size: 3em;
            font-weight: 800;
            margin-bottom: 12px;
            color: white;
            text-shadow: 0 4px 20px rgba(0,0,0,0.3);
            letter-spacing: -0.03em;
        }}
        
        .header p {{
            font-size: 1.2em;
            opacity: 0.95;
            font-weight: 400;
            color: rgba(255,255,255,0.95);
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2px;
            background: #334155;
            margin: 0;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            padding: 40px 32px;
            text-align: center;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }}
        
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #3b82f6, #8b5cf6, #ec4899);
            transform: scaleX(0);
            transition: transform 0.3s ease;
        }}
        
        .stat-card:hover {{
            background: linear-gradient(135deg, #293548 0%, #1e293b 100%);
            transform: translateY(-4px);
        }}
        
        .stat-card:hover::before {{
            transform: scaleX(1);
        }}
        
        .stat-number {{
            font-size: 3.5em;
            font-weight: 800;
            background: linear-gradient(135deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 12px;
            line-height: 1;
        }}
        
        .stat-label {{
            color: #94a3b8;
            font-size: 0.9em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }}
        
        .legend {{
            background: #1e293b;
            padding: 48px;
            border-bottom: 1px solid #334155;
        }}
        
        .legend-title {{
            font-weight: 700;
            margin-bottom: 24px;
            color: #f1f5f9;
            font-size: 1em;
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }}
        
        .gradient-container {{
            display: flex;
            align-items: center;
            gap: 24px;
        }}
        
        .gradient-bar {{
            flex: 1;
            height: 50px;
            background: linear-gradient(to right, 
                #ef4444 0%, 
                #f97316 20%,
                #f59e0b 40%, 
                #eab308 60%,
                #84cc16 80%, 
                #22c55e 100%);
            border-radius: 25px;
            box-shadow: 0 8px 32px rgba(59, 130, 246, 0.4);
            position: relative;
        }}
        
        .gradient-label {{
            color: #cbd5e1;
            font-weight: 600;
            font-size: 0.95em;
        }}
        
        .main-content {{
            padding: 48px;
            background: #0f172a;
        }}
        
        .search-container {{
            margin-bottom: 40px;
            position: relative;
        }}
        
        .search-box {{
            width: 100%;
            padding: 18px 24px 18px 56px;
            background: #1e293b;
            border: 2px solid #334155;
            border-radius: 16px;
            color: #e2e8f0;
            font-size: 1em;
            font-family: 'Inter', sans-serif;
            transition: all 0.3s ease;
        }}
        
        .search-box:focus {{
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.15);
            background: #293548;
        }}
        
        .search-icon {{
            position: absolute;
            left: 20px;
            top: 50%;
            transform: translateY(-50%);
            color: #64748b;
            font-size: 1.2em;
        }}
        
        .techniques-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
            gap: 20px;
        }}
        
        .technique-card {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 2px solid #334155;
            border-radius: 16px;
            padding: 24px;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
            position: relative;
            overflow: hidden;
        }}
        
        .technique-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #3b82f6, #8b5cf6);
            transform: scaleX(0);
            transform-origin: left;
            transition: transform 0.4s ease;
        }}
        
        .technique-card:hover {{
            transform: translateY(-8px) scale(1.02);
            border-color: #3b82f6;
            box-shadow: 0 24px 48px rgba(59, 130, 246, 0.25), 0 0 0 1px rgba(59, 130, 246, 0.1);
            background: linear-gradient(135deg, #293548 0%, #1e293b 100%);
        }}
        
        .technique-card:hover::before {{
            transform: scaleX(1);
        }}
        
        .technique-id {{
            font-weight: 800;
            font-size: 1.2em;
            margin-bottom: 16px;
            color: #f1f5f9;
            letter-spacing: -0.02em;
        }}
        
        .technique-score {{
            font-size: 0.85em;
            color: #94a3b8;
            font-weight: 500;
        }}
        
        .score-badge {{
            position: absolute;
            top: 16px;
            right: 16px;
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            color: white;
            padding: 8px 14px;
            border-radius: 24px;
            font-size: 0.8em;
            font-weight: 800;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.5);
        }}
        
        .footer {{
            background: #0f172a;
            padding: 40px 48px;
            text-align: center;
            color: #64748b;
            border-top: 1px solid #334155;
        }}
        
        .footer-title {{
            font-weight: 700;
            color: #94a3b8;
            margin-bottom: 12px;
            font-size: 1.1em;
        }}
        
        .footer-text {{
            font-size: 0.95em;
            line-height: 1.8;
        }}
        
        .footer a {{
            color: #3b82f6;
            text-decoration: none;
            font-weight: 600;
            transition: color 0.2s;
        }}
        
        .footer a:hover {{
            color: #60a5fa;
        }}
        
        .hidden {{
            display: none !important;
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 2em;
            }}
            .techniques-grid {{
                grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
                gap: 16px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>{title}</h1>
                <p>Professional MITRE ATT&CK Technique Analysis Dashboard</p>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{len(techniques)}</div>
                <div class="stat-label">Total Techniques</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{min_score:.1f}</div>
                <div class="stat-label">Minimum Score</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{max_score:.1f}</div>
                <div class="stat-label">Maximum Score</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{avg_score:.1f}</div>
                <div class="stat-label">Average Score</div>
            </div>
        </div>
        
        <div class="legend">
            <div class="legend-title">Score Intensity Gradient</div>
            <div class="gradient-container">
                <span class="gradient-label">Low</span>
                <div class="gradient-bar"></div>
                <span class="gradient-label">High</span>
            </div>
        </div>
        
        <div class="main-content">
            <div class="search-container">
                <span class="search-icon">🔍</span>
                <input type="text" class="search-box" id="searchBox" 
                       placeholder="Search techniques... (e.g., T1059, PowerShell, Command)">
            </div>
            
            <div class="techniques-grid" id="techniquesGrid">
"""
    
    sorted_techniques = sorted(techniques.items())
    
    for tech_id, tech_data in sorted_techniques:
        score = tech_data['score']
        border_color = get_color_for_score(score, min_score, max_score)
        
        html += f"""
                <div class="technique-card" style="border-color: {border_color};" 
                     data-technique="{tech_id.lower()}" data-score="{score}">
                    <div class="technique-id">{tech_id}</div>
                    <div class="technique-score">Score: {score:.1f}</div>
                    <div class="score-badge">{score:.0f}</div>
                </div>
"""
    
    html += f"""
            </div>
        </div>
        
        <div class="footer">
            <div class="footer-title">MITRE ATT&CK Heatmap Generator Pro</div>
            <div class="footer-text">
                Click any technique to view detailed information on attack.mitre.org<br>
                Press <strong>Ctrl+F</strong> to search • <strong>Ctrl+P</strong> to print
            </div>
        </div>
    </div>
    
    <script>
        // Search functionality
        const searchBox = document.getElementById('searchBox');
        const cards = document.querySelectorAll('.technique-card');
        
        searchBox.addEventListener('input', function(e) {{
            const searchTerm = e.target.value.toLowerCase();
            let visibleCount = 0;
            
            cards.forEach(card => {{
                const techniqueId = card.getAttribute('data-technique');
                if (techniqueId.includes(searchTerm) || searchTerm === '') {{
                    card.classList.remove('hidden');
                    visibleCount++;
                }} else {{
                    card.classList.add('hidden');
                }}
            }});
        }});
        
        // Click to open ATT&CK documentation
        cards.forEach(card => {{
            card.addEventListener('click', function() {{
                const techId = this.querySelector('.technique-id').textContent;
                const url = `https://attack.mitre.org/techniques/${{techId.replace('.', '/')}}/`;
                window.open(url, '_blank');
            }});
        }});
        
        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {{
            // Ctrl/Cmd + F for search
            if ((e.ctrlKey || e.metaKey) && e.key === 'f') {{
                e.preventDefault();
                searchBox.focus();
                searchBox.select();
            }}
        }});
        
        // Entrance animations
        window.addEventListener('load', function() {{
            cards.forEach((card, index) => {{
                card.style.opacity = '0';
                card.style.transform = 'translateY(30px)';
                setTimeout(() => {{
                    card.style.transition = 'all 0.6s cubic-bezier(0.4, 0, 0.2, 1)';
                    card.style.opacity = '1';
                    card.style.transform = 'translateY(0)';
                }}, index * 30);
            }});
        }});
    </script>
</body>
</html>
"""
    
    output_path = Path(output_html_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    return str(output_path)


# Keep the old functions for compatibility
generate_html_heatmap = generate_beautiful_html


def generate_svg_heatmap(navigator_json_path: str, output_svg_path: str, title: str = "MITRE ATT&CK Heatmap") -> str:
    """Generate SVG (keeping original function for compatibility)."""
    # Import from original
    from visualize_local_backup import generate_svg_heatmap as old_svg
    return old_svg(navigator_json_path, output_svg_path, title)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python visualize_beautiful.py <navigator_json_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    base_name = Path(input_file).stem
    
    html_path = f"output/{base_name}_heatmap.html"
    
    print(f"Generating beautiful visualization from: {input_file}")
    html_output = generate_beautiful_html(input_file, html_path)
    print(f"✓ Beautiful HTML heatmap: {html_output}")
    print(f"  Open in browser to view!")
    print()
    print("Done! Your professional heatmap is ready.")
