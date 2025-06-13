#!/usr/bin/env python3

import json
import requests
from urllib.parse import urlparse
import sys
import time
from datetime import datetime, timedelta
import re

def get_latest_ct_logs_url():
    """Find and return the URL of the most recent CT logs JSON file."""
    base_url = "https://storage.googleapis.com/crlite-filters-prod"
    
    # Start from today and go backwards until we find a valid file
    current_date = datetime.now()
    max_attempts = 7  # Look back up to 7 days
    
    for _ in range(max_attempts):
        # Try version 1 first (more recent), then version 0
        for version in [1, 0]:
            date_str = current_date.strftime("%Y%m%d")
            url = f"{base_url}/{date_str}-{version}/ct-logs.json"
            
            try:
                response = requests.head(url, timeout=5)
                if response.status_code == 200:
                    return url
            except requests.RequestException:
                continue
        
        # Move to previous day if no valid file found
        current_date -= timedelta(days=1)
    
    raise Exception("Could not find a valid CT logs JSON file in the last 7 days")

def download_ct_logs(url):
    """Download and parse the CT logs JSON file from the given URL."""
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise Exception(f"Failed to download CT logs: {str(e)}")
    except json.JSONDecodeError as e:
        raise Exception(f"Invalid JSON in downloaded file: {str(e)}")

def get_sth(log_url):
    """Get the Signed Tree Head from a CT log server."""
    try:
        # Ensure URL has https:// prefix
        if not log_url.startswith('http'):
            log_url = f'https://{log_url}'
        
        # Add /ct/v1/get-sth endpoint
        if not log_url.endswith('/ct/v1/get-sth'):
            log_url = f'{log_url.rstrip("/")}/ct/v1/get-sth'
        
        # Make request with timeout
        response = requests.get(log_url, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return None

def process_log(log_entry):
    """Process a single log entry and return its analysis."""
    short_url = log_entry['ShortURL']
    log_id = log_entry['LogID']
    min_entry = log_entry['MinEntry']
    max_entry = log_entry['MaxEntry']
    max_timestamp = log_entry['MaxTimestamp']
    
    # Skip logs with empty LogID (inactive logs)
    if not log_id:
        return None
    
    # Get current tree size
    sth = get_sth(short_url)
    if not sth or 'tree_size' not in sth or 'timestamp' not in sth:
        return {
            'short_url': short_url,
            'log_id': log_id,
            'min_entry': min_entry,
            'max_entry': max_entry,
            'tree_size': 'N/A',
            'ratio': 'N/A',
            'time_diff': 'N/A',
            'error': 'Failed to get STH'
        }
    
    tree_size = sth['tree_size']
    sth_timestamp = sth['timestamp']
    
    # Calculate time difference in hours
    if max_timestamp > 0 and sth_timestamp > 0:
        time_diff_hours = (sth_timestamp - max_timestamp) / (1000 * 60 * 60)  # Convert ms to hours
        time_diff_str = f"{time_diff_hours:+.2f}h"  # + or - sign to show direction
    else:
        time_diff_str = 'N/A'
    
    # Calculate ratio if both values are valid
    if tree_size > 0:
        ratio = (max_entry / tree_size) * 100
        ratio_str = f"{ratio:.2f}%"
    else:
        ratio_str = 'N/A'
    
    return {
        'short_url': short_url,
        'log_id': log_id,
        'min_entry': min_entry,
        'max_entry': max_entry,
        'tree_size': tree_size,
        'ratio': ratio_str,
        'time_diff': time_diff_str,
        'error': None
    }

def main():
    try:
        # Get the URL of the most recent CT logs file
        print("Finding most recent CT logs file...", file=sys.stderr)
        logs_url = get_latest_ct_logs_url()
        print(f"Downloading from: {logs_url}", file=sys.stderr)
        
        # Download and parse the JSON file
        logs = download_ct_logs(logs_url)
        
        print(f"Processing {len(logs)} CT logs...", file=sys.stderr)
        
        results = []
        logs.sort(key=lambda x: x["ShortURL"])
        for log in logs:
            result = process_log(log)
            if result is None:
                continue
            
            entry_lag = int(result['tree_size']) - int(result['max_entry']) if result['tree_size'] != 'N/A' else 'N/A'
            results.append({
                'url': result['short_url'],
                'entry_lag': entry_lag,
                'time_diff': result['time_diff'],
                'tree_size': result['tree_size'],
                'error': result['error']
            })
        
        # Output JSON to stdout
        print(json.dumps(results, indent=2))
                
    except FileNotFoundError:
        print("Error: ct-logs.json not found", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print("Error: Invalid JSON in ct-logs.json", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main() 
