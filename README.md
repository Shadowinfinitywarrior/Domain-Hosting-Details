# Domain Lookup Tool

This is a Flask-based web application that allows users to perform detailed domain lookups, including WHOIS data, DNS information, IP analysis, security data, and more. The project integrates multiple APIs and tools to gather comprehensive information about a domain.

## Features

- **WHOIS Lookup**: Fetch WHOIS information for a given domain.
- **DNS Information**: Get DNS records, nameservers, and IP address.
- **IP Info**: Retrieve IP address information such as location and organization.
- **DNS History**: View DNS record history using SecurityTrails.
- **Subdomain Enumeration**: Enumerate subdomains of the domain.
- **Reverse IP Lookup**: Find domains hosted on the same server.
- **HTTP Header Analysis**: Analyze HTTP headers of the domain.
- **SSL/TLS Certificate Transparency**: View certificate transparency logs.
- **Reverse DNS Lookup**: Perform reverse DNS lookup.
- **Port Scanning**: Scan ports on the domain’s server.
- **Traceroute**: Trace the network route to the domain.
- **BGP Data**: View Border Gateway Protocol (BGP) data for the domain.
- **MX Lookup**: View mail server (MX) records.
- **Shodan IP Lookup**: Fetch security data about the domain’s IP from Shodan.
- **DNSDumpster Lookup**: Placeholder for DNS Dumpster data.
- **SecurityTrails Lookup**: Fetch detailed domain data using SecurityTrails.
- **ThreatCrowd Lookup**: View domain or IP reports from ThreatCrowd.

## Setup Instructions

### Prerequisites

- Python 3.x
- Flask
- External libraries: `requests`, `dnspython`, `whois`, `shodan`
- APIs: Shodan API, SecurityTrails API

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/domain-lookup-tool.git
   cd domain-lookup-tool
