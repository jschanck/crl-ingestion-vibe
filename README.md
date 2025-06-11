⚠️ **Warning**: This project is largely AI generated.

# CRLite CRL ingestion status dashboard

A dashboard for monitoring the status of CRL (Certificate Revocation List) ingestion from various certificate authorities. The dashboard displays a heatmap visualization of CRL download statuses over time, helping identify patterns and issues in CRL ingestion.

## Features

- Visual heatmap showing CRL ingestion status over time
- Color-coded status indicators:
  - Green: Valid CRL
  - Yellow: Warning or old valid CRL (>2 weeks)
  - Red: Error
  - Gray: No data
- Interactive hover details showing:
  - CRL age
  - Number of revocations
  - Status kind
  - Error messages (if any)
- Automatic data fetching and caching
- Daily updates of CRL status data

## Usage

Run main.py then open output.html.
