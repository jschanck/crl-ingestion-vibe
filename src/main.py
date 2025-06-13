import sys
import json
import requests
import re
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime, timedelta
from pathlib import Path
import os
import time
import subprocess

CACHE_DIR = Path("cache")
BASE_URL = "https://storage.googleapis.com/crlite-filters-prod"
DAYS_TO_FETCH = 14 
FILES_PER_DAY = 2

def get_file_dates() -> List[str]:
    """
    Generate list of dates for the last 45 days in YYYYMMDD format.
    """
    dates = []
    today = datetime.now()
    for i in range(DAYS_TO_FETCH):
        date = today - timedelta(days=i)
        dates.append(date.strftime("%Y%m%d"))
    return dates

def get_file_urls() -> List[Tuple[str, str]]:
    """
    Generate list of (date-suffix, url) tuples for all files to fetch.
    Returns list of tuples containing (date-suffix, url) for each file.
    Example: ("20250610-1", "https://.../20250610-1/crl-audit.json")
    """
    urls = []
    for date in get_file_dates():
        for suffix in range(FILES_PER_DAY):
            date_suffix = f"{date}-{suffix}"
            url = f"{BASE_URL}/{date_suffix}/crl-audit.json"
            urls.append((date_suffix, url))
    return urls

def get_cache_path(date_suffix: str) -> Path:
    """Get the cache file path for a given date-suffix."""
    return CACHE_DIR / f"{date_suffix}.json"

def fetch_json_data(url: str, cache_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Fetch JSON data from a URL, optionally caching the result.
    
    Args:
        url (str): URL to fetch JSON data from
        cache_path (Optional[Path]): Path to cache the result
        
    Returns:
        Dict[str, Any]: Parsed JSON data
        
    Raises:
        requests.RequestException: If the request fails
        json.JSONDecodeError: If the response is not valid JSON
    """
    if cache_path and cache_path.exists():
        with open(cache_path, 'r') as f:
            return json.load(f)
    
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()
    
    if cache_path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, 'w') as f:
            json.dump(data, f)
    
    return data

def check_for_updates() -> List[Tuple[str, str]]:
    """
    Check which files need to be updated.
    Returns list of (date-suffix, url) tuples for files that need updating.
    """
    needs_update = []
    for date_suffix, url in get_file_urls():
        cache_path = get_cache_path(date_suffix)
        if not cache_path.exists():
            needs_update.append((date_suffix, url))
    return needs_update

def update_files(needs_update: List[Tuple[str, str]]) -> None:
    """Update the specified files and remove unexpected files from the cache."""
    # Get all expected date_suffixes from get_file_urls()
    expected_date_suffixes = {date_suffix for date_suffix, _ in get_file_urls()}
    expected_files = {get_cache_path(date_suffix) for date_suffix in expected_date_suffixes}
    cache_files = set(CACHE_DIR.glob("*"))
    # Remove unexpected files
    for file_path in cache_files - expected_files:
        try:
            file_path.unlink()
            print(f"Removed unexpected file: {file_path}")
        except Exception as e:
            print(f"Error removing {file_path}: {e}")

    # Update expected files
    for date_suffix, url in needs_update:
        print(f"Fetching {date_suffix}...")
        cache_path = get_cache_path(date_suffix)
        try:
            fetch_json_data(url, cache_path)
            print(f"Successfully updated {date_suffix}")
        except Exception as e:
            print(f"Error updating {date_suffix}: {e}")

def load_cached_data() -> Dict[str, Dict[str, Any]]:
    """
    Load all cached data files.
    Returns a dictionary mapping issuer subjects to their statuses in each file.
    """
    issuer_statuses = {}  # Maps issuer subject to dict of file statuses
    file_dates = []  # List of date-suffixes in order
    
    # First pass: collect all unique issuers and file dates
    for date_suffix, url in sorted(get_file_urls()):
        file_dates.append(date_suffix)
        cache_path = get_cache_path(date_suffix)
        if cache_path.exists():
            try:
                with open(cache_path, 'r') as f:
                    data = json.load(f)
                    for entry in data.get('Entries', []):
                        if 'Not Fresh' in entry.get('Kind', 'N/A'):
                            continue
                        key = entry.get('Url', 'N/A')
                        if key not in issuer_statuses:
                            issuer_statuses[key] = {
                                'url': entry.get('Url', ''),
                                'issuer': entry.get('IssuerSubject', 'N/A'),
                                'statuses': {}
                            }
                        issuer_statuses[key]['statuses'][date_suffix] = {
                            'kind': entry.get('Kind', 'N/A'),
                            'num_revocations': entry.get('NumRevocations', '0'),
                            'errors': entry.get('Errors', ''),
                            'age': entry.get('Age', 'N/A'),
                            'sha256sum': entry.get('SHA256Sum', 'N/A')
                        }
            except Exception as e:
                print(f"Error loading {date_suffix}: {e}")
    
    return issuer_statuses, file_dates

def is_valid(kind: str) -> Tuple[bool, str]:
    """
    Determine if an entry is valid and its status type.
    
    Args:
        kind (str): The kind/status of the entry
        
    Returns:
        Tuple[bool, str]: A tuple containing:
            - bool: True if the entry is valid or empty, False otherwise
            - str: The status type ('valid', 'warning', or 'error')
    """
    if 'Valid' in kind or 'Empty' in kind:
        return True, 'valid'
    elif 'Warning' in kind:
        return False, 'warning'
    else:
        return False, 'error'


def get_status_color(kind: str, age: str) -> str:
    """
    Determine the background color based on the entry kind.

    Args:
        kind (str): The kind/status of the entry
        age (str): The age of the entry

    Returns:
        str: CSS color value
    """
    _, status = is_valid(kind)
    if status == 'valid':
        color = '#90EE90'
        try:
            # Extract hours from age string (e.g., "1659h12m26.81016978s")
            hours = int(age.split('h')[0])
            if hours > 336:  # More than 2 weeks
                color = '#FFEB3B'  # Light yellow for old valid entries
        except (ValueError, IndexError):
            pass
        return color
    elif status == 'warning':
        return '#FFEB3B'  # Light yellow
    else:
        return '#FFB6C1'  # Light red


def create_heatmap_html(issuer_statuses: Dict[str, Dict[str, Any]], file_dates: List[str]) -> str:
    """Create a heatmap visualization using CSS Grid."""
    # Sort issuers by priority of issues, then by URL
    def sort_key(issuer):
        data = issuer_statuses[issuer]
        # Priority levels: 0=no issues, 1=arrows, 2=missing data, 3=warnings, 4=errors
        priority = 0
        has_error = False
        has_warning = False
        has_arrow = False
        prev_revocations = None
        
        # Check for missing data
        if len(data['statuses']) < len(file_dates):
            priority = 2
        
        # Check for warnings, errors, and arrows
        for status in data['statuses'].values():
            kind = status.get('kind', '')
            age = status.get('age', '')
            bg_color = get_status_color(kind, age)
            if bg_color == '#FFB6C1':  # Red
                has_error = True
            elif bg_color == '#FFEB3B':  # Yellow
                has_warning = True
            
            # Check for significant revocation count changes
            curr_revocations = status.get('num_revocations', 0)
            if prev_revocations is not None and isinstance(curr_revocations, int) and isinstance(prev_revocations, int):
                if abs(curr_revocations - prev_revocations) > 250:
                    has_arrow = True
            prev_revocations = curr_revocations
        
        # Set priority based on most severe issue
        if has_error:
            priority = 4
        elif has_warning:
            priority = 3
        elif has_arrow:
            priority = 1
        
        # Sort by priority (descending) then by URL
        return (-priority, data['url'].lower())
    
    sorted_issuers = sorted(issuer_statuses.keys(), key=sort_key)
    
    if not sorted_issuers:
        return "<div>No warnings or errors found in any URLs.</div>"
    
    # Create the grid container with CSS Grid
    html = """
    <div class="heatmap-container">
        <h2>CRL Ingestion Status</h2>
        <div class="info-panel">
            <div class="info-content">
                <div class="info-title">Hover over a cell to see details</div>
                <div class="info-details"></div>
            </div>
        </div>
        <div class="heatmap-header">
        <div class="date-header"></div>\n"""
    
    # Add date headers
    for date_suffix in file_dates:
        html += f'<div class="date-header">{date_suffix}</div>\n'
    
    html += '</div>\n<div class="heatmap-grid">\n'
    
    # Build JS tables for issuers and dates
    row_issuers_js = 'window.rowIssuersByIdx = ' + json.dumps({i: issuer_statuses[issuer]['issuer'] for i, issuer in enumerate(sorted_issuers)}) + ';'
    col_dates_js = 'window.colDatesByIdx = ' + json.dumps({i: date for i, date in enumerate(file_dates)}) + ';'
    html += f'<script>{row_issuers_js}{col_dates_js}</script>'

    # Add rows for each issuer
    for row_idx, issuer in enumerate(sorted_issuers):
        url = issuer_statuses[issuer]['url']
        display_url = url[:40] + ('...' if len(url) > 40 else '')
        statuses = issuer_statuses[issuer]['statuses']
        html += f'<div class="url-column"><a href="{url}" target="_blank">{display_url}</a></div>\n'
        prev_revocations = None
        for col_idx, date_suffix in enumerate(file_dates):
            if date_suffix in statuses:
                status = statuses[date_suffix]
                kind = status['kind']
                age = status['age']
                bg_color = get_status_color(kind, age)
                curr_revocations = status.get('num_revocations', 0)
                rev_change = 0
                display_text = ''
                if prev_revocations is not None and isinstance(curr_revocations, int) and isinstance(prev_revocations, int):
                    rev_change = curr_revocations - prev_revocations
                    if abs(rev_change) > 250:
                        if rev_change > 0:
                            display_text = '&#9650;'
                        elif rev_change < 0:
                            display_text = '&#9660;'
                prev_revocations = curr_revocations
                cell_data = {
                    "kind": kind,
                    "errors": status.get("errors", ""),
                    "revocations": curr_revocations,
                    "rev_change": rev_change,
                    "age": status.get("age", "N/A"),
                    "sha256sum": status.get("sha256sum", "xxx"),
                    "row_idx": row_idx,
                    "col_idx": col_idx
                }
                cell_data_json = json.dumps(cell_data).replace("'", "&#39;")
                html += f'''
                <div class="status-cell" 
                     style="background-color: {bg_color};"
                     data-cell='{cell_data_json}'>{display_text}</div>
                '''
            else:
                html += '<div class="status-cell" style="background-color: #f0f0f0;" data-cell=\'{"row_idx": ' + str(row_idx) + ', "col_idx": ' + str(col_idx) + '}\'></div>\n'
                prev_revocations = None
    
    html += """</div></div>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        const infoPanel = document.querySelector('.info-panel');
        const infoDetails = document.querySelector('.info-details');
        const infoTitle = document.querySelector('.info-title');
        const cells = document.querySelectorAll('.status-cell');
        
        // Update panel position on mouse move
        document.addEventListener('mousemove', function(e) {
            // Add offset to prevent panel from covering the cursor
            const x = e.clientX + 15;
            const y = e.clientY + 15;
            
            // Keep panel within viewport bounds
            const panelRect = infoPanel.getBoundingClientRect();
            const maxX = window.innerWidth - panelRect.width;
            const maxY = window.innerHeight - panelRect.height;
            
            infoPanel.style.left = Math.min(x, maxX) + 'px';
            infoPanel.style.top = Math.min(y, maxY) + 'px';
        });
        
        cells.forEach(cell => {
            cell.addEventListener('mouseenter', function() {
                const data = JSON.parse(this.dataset.cell);
                if (data.kind) {
                    const issuer = window.rowIssuersByIdx[data.row_idx] || 'N/A';
                    const date = window.colDatesByIdx[data.col_idx] || 'N/A';
                    let html = `<div class="info-row"><strong>Date:</strong> ${date}</div>`;
                    html += `<div class="info-row"><strong>Sha256:</strong> ${data.sha256sum}</div>`;
                    html += `<div class="info-row"><strong>Age:</strong> ${data.age}</div>`;
                    html += `<div class="info-row"><strong>Kind:</strong> ${data.kind}</div>`;
                    if (data.revocations) {
                        let revText = `<strong>Revocations:</strong> ${data.revocations}`;
                        if (data.rev_change !== null) {
                            const changeText = data.rev_change > 0 ? 
                                ` (+${data.rev_change})` : 
                                ` (${data.rev_change})`;
                            revText += changeText;
                        }
                        html += `<div class="info-row">${revText}</div>`;
                    }
                    if (data.errors) {
                        html += `<div class="info-row"><strong>Errors:</strong> ${data.errors}</div>`;
                    }
                    infoDetails.innerHTML = html;
                    infoTitle.textContent = issuer;
                    infoPanel.style.display = 'block';
                } else {
                    infoDetails.innerHTML = `<div class="info-row">No data available for ${data.row_idx}, ${data.col_idx}</div>`;
                    infoTitle.textContent = 'No Data';
                    infoPanel.style.display = 'block';
                }
            });
            
            cell.addEventListener('mouseleave', function() {
                infoPanel.style.display = 'none';
                infoDetails.innerHTML = '';
                infoTitle.textContent = 'Hover over a cell to see details';
            });
        });
    });
    </script>
    """
    return html

def get_ct_log_data() -> List[Dict[str, Any]]:
    """Get CT log data by running ct_status.py."""
    try:
        result = subprocess.run(['python3', 'ct_status.py'], 
                              capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        print(f"Error getting CT log data: {e}", file=sys.stderr)
        return []

def create_ct_log_table(ct_logs: List[Dict[str, Any]]) -> str:
    """Create an HTML table showing CT log data."""
    if not ct_logs:
        return "<div>No CT log data available.</div>"
    
    html = """
    <div class="ct-log-table">
        <h2>CT Log Ingestion Status</h2>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Tree Size</th>
                    <th>Entry Lag</th>
                    <th>Timestamp lag</th>
                </tr>
            </thead>
            <tbody>
    """
    
    # Sort by time difference (if available) and then by URL
    def parse_time_diff(time_str):
        if not time_str or time_str == 'N/A':
            return float('inf')
        try:
            # Convert time string (e.g. "+12.5h" or "-2.3h") to hours
            hours = float(time_str.replace('h', ''))
            return abs(hours)  # Use absolute value for sorting
        except (ValueError, AttributeError):
            return float('inf')
    
    def format_number(num):
        if isinstance(num, int):
            return f"{num:,}"
        return str(num)
    
    def sort_key(log):
        time_diff = parse_time_diff(log['time_diff'])
        return (time_diff, log['url'])
    
    sorted_logs = sorted(ct_logs, key=sort_key, reverse=True)
    
    for log in sorted_logs:
        url = log['url']
        entry_lag = log['entry_lag']
        time_diff = log['time_diff']
        tree_size = log['tree_size']
        error = log.get('error')
        
        # Determine row class based on time difference and errors
        row_class = ''
        if error:
            row_class = 'error-row'
        else:
            hours = parse_time_diff(time_diff)
            if hours == float('inf'):
                row_class = 'error-row'  # Treat N/A as error
            elif hours > 24:  # More than 24 hours
                row_class = 'warning-row'
            elif hours > 12:  # More than 12 hours
                row_class = 'notice-row'
            else:
                row_class = 'good-row'
        
        html += f'<tr class="{row_class}">'
        html += f'<td><a href="https://{url}" target="_blank">{url}</a></td>'
        html += f'<td class="number-cell">{format_number(tree_size)}</td>'
        html += f'<td class="number-cell">{format_number(entry_lag)}</td>'
        html += f'<td>{time_diff}</td>'
        if error:
            html += f'<td class="error-message">{error}</td>'
        html += '</tr>\n'
    
    html += """
            </tbody>
        </table>
    </div>
    """
    return html

def main() -> None:
    """Main entry point of the application."""
    # Check for files that need updating
    needs_update = check_for_updates()
    
    if needs_update:
        update_files(needs_update)
    
    # Load all cached data
    issuer_statuses, file_dates = load_cached_data()
    
    if not issuer_statuses:
        print("No data available. Please run the script again to download the files.")
        sys.exit(1)

    # Get CT log data
    ct_logs = get_ct_log_data()

    # Start building the HTML output
    html_output = """
    <html>
    <head>
        <title>CRLite CT Log and CRL Ingestion Vibes</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                margin: 20px;
                font-size: 13px;  /* Set base font size to match heatmap */
            }
            .heatmap-container {
                display: flex;
                flex-direction: column;
                gap: 0;  /* Remove gap between header and grid */
                background-color: #ddd;
                padding: 1px;
                border-radius: 4px;
                overflow: auto;
                max-width: fit-content;
            }
            .info-panel {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 12px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                position: fixed;
                pointer-events: none;  /* Allow clicking through the panel */
                max-width: 500px;
                z-index: 1000;
            }
            .info-title {
                font-weight: bold;
                margin-bottom: 8px;
                color: #333;
            }
            .info-details {
                font-size: 14px;
            }
            .info-row {
                margin-bottom: 4px;
            }
            .info-row:last-child {
                margin-bottom: 0;
            }
            .info-row strong {
                color: #666;
                margin-right: 4px;
            }
            .heatmap-header {
                display: grid;
                grid-template-columns: minmax(200px, auto) repeat(""" + str(len(file_dates)) + """, 20px);
                background: #fafafa;
            }
            .heatmap-grid {
                display: grid;
                grid-template-columns: minmax(200px, auto) repeat(""" + str(len(file_dates)) + """, 20px);
                background: #fff;
            }
            .url-column {
                padding: 2px 6px;
                border: 1px solid #eee;
                background: #fff;
                font-size: 13px;
                word-break: break-all;
            }
            .status-cell {
                width: 20px;
                height: 20px;
                border: 1px solid #eee;
                text-align: center;
                font-size: 13px;
                background: inherit;
                padding: 0;
                margin: 0;
            }
            .date-header {
                font-size: 12px;
                text-align: center;
                padding: 2px 0;
                border: 1px solid #eee;
                background: #fafafa;
                writing-mode: vertical-rl;
                transform: rotate(180deg);
                height: 100px;
                white-space: nowrap;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            h1, h2 {
                color: #333;
                margin-bottom: 20px;
                font-size: 24px;  /* Consistent heading size */
            }
            h2 {
                margin-top: 40px;
            }
            a {
                color: #0066cc;
                text-decoration: none;
            }
            a:hover {
                text-decoration: underline;
            }
            /* CT Log table styles */
            .ct-log-table {
                margin-top: 40px;
                margin-bottom: 40px;
            }
            .ct-log-table table {
                border-collapse: collapse;
                width: 100%;
                max-width: 1200px;
                margin-top: 10px;
                font-size: 13px;
            }
            .ct-log-table th, .ct-log-table td {
                padding: 8px;
                text-align: left;
                border: 1px solid #ddd;
            }
            .ct-log-table .number-cell {
                text-align: right;
                font-family: monospace;
            }
            .ct-log-table .error-row {
                background-color: #ffebee;  /* Light red */
            }
            .ct-log-table .warning-row {
                background-color: #fff3e0;  /* Light orange */
            }
            .ct-log-table .notice-row {
                background-color: #fffde7;  /* Light yellow */
            }
            .ct-log-table .good-row {
                background-color: #e8f5e9;  /* Light green */
            }
            .ct-log-table .error-message {
                color: #d32f2f;
                font-style: italic;
            }
        </style>
    </head>
    <body>
    """
    
    # Add the CT log table
    html_output += create_ct_log_table(ct_logs)

    # Add the heatmap
    html_output += create_heatmap_html(issuer_statuses, file_dates)

    # Close the HTML tags
    html_output += """
    </body>
    </html>
    """

    # Write the HTML output to a file
    with open("output.html", "w", encoding="utf-8") as f:
        f.write(html_output)
    # Write issuer_statuses to JSON file
    with open("issuer_statuses.json", "w", encoding="utf-8") as f:
        json.dump(issuer_statuses, f, indent=4)


if __name__ == "__main__":
    main()
