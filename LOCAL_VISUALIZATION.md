# Local Visualization Guide

## 🎨 **Generate Beautiful Heatmaps Locally - No Upload Needed!**

Your tool now **automatically generates local HTML and SVG heatmaps** - no need to upload to Navigator!

## 🚀 **Quick Start**

### **Option 1: Automatic (Recommended)**

Just run your normal command - visualizations are created automatically:

```bash
python heatmap_gen.py techniques -i input-ttps.json -o my_analysis -t "My TTPs"
```

**This creates 3 files:**
1. ✅ `output/my_analysis.json` - Navigator format (for upload if you want)
2. ✅ `output/my_analysis_heatmap.html` - **Interactive HTML heatmap**
3. ✅ `output/my_analysis_heatmap.svg` - **SVG image**

### **Option 2: Manual Generation**

If you already have a Navigator JSON file:

```bash
python visualize_local.py output/my_analysis.json
```

## 📊 **What You Get**

### **1. Interactive HTML Heatmap**

Open `output/my_analysis_heatmap.html` in your browser to see:

- 🎨 **Beautiful gradient colors** (red → yellow → green)
- 📊 **Statistics dashboard** (total techniques, min/max scores, average)
- 🎯 **Click any technique** to open its ATT&CK page
- 📱 **Responsive design** (works on mobile too!)
- 🖨️ **Print-friendly** (Ctrl+P to print)
- ✨ **Hover effects** for better UX

**Features:**
- Gradient legend showing score intensity
- Organized by technique ID
- Shows score on each card
- Click to open ATT&CK documentation
- No internet required (works offline!)

### **2. SVG Image**

Open `output/my_analysis_heatmap.svg` in:
- 🌐 Any web browser
- 🎨 Image editors (Inkscape, Illustrator, etc.)
- 📄 Include in documents/presentations
- 📧 Email as attachment

**Perfect for:**
- Presentations (PowerPoint, Google Slides)
- Reports (Word, PDF)
- Documentation
- Printing high-quality posters

## 📖 **Examples**

### **Example 1: Your Threat Intel**

```bash
python heatmap_gen.py techniques -i input-ttps.json -o my_ttps -t "My Threat Intelligence"

# Opens these files:
# - output/my_ttps_heatmap.html  ← Open this in Chrome/Firefox
# - output/my_ttps_heatmap.svg   ← Use in presentations
```

### **Example 2: Energy Sector Analysis**

```bash
python heatmap_gen.py groups -s energy -o energy -t "Energy Sector Threats"

# Opens these files:
# - output/energy_heatmap.html  ← Interactive dashboard
# - output/energy_heatmap.svg   ← High-quality image
```

### **Example 3: APT Comparison**

```bash
python heatmap_gen.py groups -s apt --threshold 5 -o apt_common -t "Common APT Techniques"

# Opens these files:
# - output/apt_common_heatmap.html  ← See the patterns!
# - output/apt_common_heatmap.svg   ← Save for later
```

## 🎯 **How to Use the HTML Heatmap**

### **Step 1: Generate**
```bash
python heatmap_gen.py techniques -i input-ttps.json -o analysis -t "Analysis"
```

### **Step 2: Open in Browser**
```bash
# Windows
start output/analysis_heatmap.html

# Mac
open output/analysis_heatmap.html

# Linux
xdg-open output/analysis_heatmap.html

# Or just double-click the file!
```

### **Step 3: Explore**
- **View statistics** at the top
- **See color gradient** legend
- **Click any technique** to learn more
- **Press Ctrl+P** to print
- **Share the HTML file** with your team (it's standalone!)

## 🎨 **Understanding the Colors**

| Color | Meaning |
|-------|---------|
| 🔴 **Red** | Low score (less common/fewer groups) |
| 🟡 **Yellow** | Medium score |
| 🟢 **Green** | High score (very common/many groups) |

The gradient smoothly transitions between these colors based on your scores.

## 📱 **Mobile Friendly**

The HTML heatmap works great on:
- 📱 Phones
- 📱 Tablets  
- 💻 Laptops
- 🖥️ Desktops

Just open the HTML file on any device!

## 🔄 **Regenerate Anytime**

Already have Navigator JSON files? Convert them:

```bash
# Convert existing Navigator JSON to local heatmap
python visualize_local.py output/old_analysis.json

# Creates:
# - output/old_analysis_heatmap.html
# - output/old_analysis_heatmap.svg
```

## 📊 **Compare Multiple Heatmaps**

Open multiple HTML files in different browser tabs:

```bash
# Generate several analyses
python heatmap_gen.py groups -s energy -o energy -t "Energy"
python heatmap_gen.py groups -s financial -o finance -t "Financial"
python heatmap_gen.py groups -s healthcare -o health -t "Healthcare"

# Now open all three HTML files in your browser
# Compare them side-by-side!
```

## 🎨 **Use Cases**

### **For Presentations**
1. Generate SVG: `python heatmap_gen.py groups -s ransomware -o ransomware -t "Ransomware"`
2. Open `output/ransomware_heatmap.svg` in PowerPoint
3. Insert as image - scales perfectly!

### **For Reports**
1. Generate HTML: `python heatmap_gen.py techniques -i ttps.json -o report -t "Q1 Report"`
2. Open in browser
3. Press Ctrl+P → "Save as PDF"
4. Include in your report!

### **For Team Sharing**
1. Generate: `python heatmap_gen.py groups -s apt -o apt_brief -t "APT Brief"`
2. Email `output/apt_brief_heatmap.html` to team
3. They can open it without any tools!

### **For Documentation**
1. Generate SVG
2. Include in Markdown/Wiki
3. Always up-to-date visual reference

## 🆘 **Troubleshooting**

### **"visualize_local.py not found"**
Make sure you're in the project directory:
```bash
cd mitre-attack-heatmap-pro
python visualize_local.py output/my_analysis.json
```

### **HTML file won't open**
Try opening manually:
- Right-click the HTML file
- "Open with" → Your browser (Chrome, Firefox, Edge)

### **SVG looks blank**
- SVG files need a viewer (browser, image editor)
- Try opening in Chrome/Firefox
- Or use an SVG editor like Inkscape

### **Colors don't show**
Make sure you have scores in your data:
- Check that techniques have scores > 0
- Verify the JSON file is valid

## 🎉 **Best Practices**

1. **Always generate both HTML and SVG**
   - HTML for interactive exploration
   - SVG for presentations/documents

2. **Use descriptive titles**
   ```bash
   python heatmap_gen.py techniques -i ttps.json -o analysis -t "Q1 2024 Threat Landscape Analysis"
   ```

3. **Organize your outputs**
   ```bash
   # Create dated folders
   mkdir -p output/2024-02-16
   python heatmap_gen.py groups -s energy -o 2024-02-16/energy -t "Energy Analysis"
   ```

4. **Share HTML files via**
   - Email (they're standalone)
   - Shared drives
   - Internal wiki/documentation
   - Slack/Teams

## 🚀 **Advanced Tips**

### **Batch Generate Multiple**
```bash
# Windows batch script
for %%i in (energy financial healthcare retail) do (
    python heatmap_gen.py groups -s %%i -o %%i -t "%%i Sector"
)
```

### **Custom Styling**
The HTML files are editable! Open in a text editor and modify:
- Colors in the CSS `<style>` section
- Layout and spacing
- Add your company logo

### **Automate Reports**
```python
# daily_report.py
import subprocess
from datetime import date

today = date.today().strftime("%Y-%m-%d")
subprocess.run([
    "python", "heatmap_gen.py", "groups", 
    "-s", "apt", 
    "-o", f"daily/{today}_apt", 
    "-t", f"APT Analysis {today}"
])
```

## 📚 **Summary**

**You now have TWO ways to view heatmaps:**

1. **Local** (New! No upload needed)
   - Interactive HTML in browser
   - SVG for presentations
   - Works offline
   - Perfect for quick analysis

2. **ATT&CK Navigator** (Original)
   - Upload JSON to Navigator
   - Full ATT&CK integration
   - Advanced features
   - Online tool

**Choose based on your needs:**
- 🏠 **Local** = Fast, offline, easy sharing
- 🌐 **Navigator** = Full features, online, standard format

Both work great! Use whichever fits your workflow. 🎯
