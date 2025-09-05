import requests
import json
import os
from datetime import datetime

ABUSE_API_KEY = "e44a649fbd881df243036ab4234032e9673c41993acd2689826a2056fc7dec159b6de091db24af05"
CACHE_DIR = "cache/ip_intel"

def is_ip_malicious(ip):
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 30}
        )
        data = response.json()
        return data["data"]["abuseConfidenceScore"] > 50
    except Exception as e:
        return False

def get_full_ip_analysis(ip):
    """
    Perform comprehensive analysis of an IP address from multiple sources
    Returns a dict with all available intelligence
    """
    result = {
        "ip": ip,
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sources": [],
        "risk_score": 0,
        "is_malicious": False,
        "categories": [],
        "geolocation": None,
        "is_tor_exit": False,
        "is_proxy": False,
        "is_datacenter": False,
        "whois": None,
        "related_ips": [],
        "history": get_ip_history(ip)
    }
    
    # First check cached data
    cached = get_cached_analysis(ip)
    if cached and (datetime.now() - datetime.strptime(cached["analysis_time"], "%Y-%m-%d %H:%M:%S")).total_seconds() < 3600:
        return cached
    
    # Get AbuseIPDB data
    abuse_data = get_abuseipdb_data(ip)
    if abuse_data:
        result["sources"].append("AbuseIPDB")
        result["abuseipdb"] = abuse_data
        result["is_malicious"] = abuse_data["abuseConfidenceScore"] > 50
        result["geolocation"] = {
            "country": abuse_data.get("countryCode", ""),
            "country_name": abuse_data.get("countryName", ""),
            "city": "",  # AbuseIPDB doesn't provide city
            "latitude": "",
            "longitude": ""
        }
        result["is_datacenter"] = "hosting" in abuse_data.get("usageType", "").lower()
        
        # Extract abuse categories
        if "reports" in abuse_data and len(abuse_data["reports"]) > 0:
            categories = []
            for report in abuse_data["reports"]:
                if "categories" in report:
                    for cat in report["categories"]:
                        categories.append(get_abuse_category_name(cat))
            result["categories"] = list(set(categories))  # Deduplicate
    
    # Check if it's a TOR exit node
    is_tor = check_tor_exit_node(ip)
    if is_tor:
        result["sources"].append("TOR Exit List")
        result["is_tor_exit"] = True
        result["categories"].append("TOR Exit Node")
    
    # Get additional geolocation data if not from AbuseIPDB
    if not result["geolocation"] or not result["geolocation"]["country"]:
        geo_data = get_ip_geolocation(ip)
        if geo_data:
            result["sources"].append("IP-API")
            result["geolocation"] = geo_data
    
    # Calculate overall risk score (weighted)
    risk_score = 0
    if result["is_malicious"]:
        risk_score += 50  # Base score if determined malicious
    
    if "abuseipdb" in result:
        risk_score += min(result["abuseipdb"].get("abuseConfidenceScore", 0) * 0.4, 40)  # Up to 40 points from abuse score
    
    if result["is_tor_exit"]:
        risk_score += 20  # Add 20 points if it's a TOR exit node
    
    if result["is_proxy"]:
        risk_score += 15  # Add 15 points if it's a proxy
    
    # Add risk based on categories
    high_risk_categories = ["Web Spam", "SSH", "Email Spam", "Port Scan", "Hacking"]
    for category in result["categories"]:
        if category in high_risk_categories:
            risk_score += 5  # Add 5 points per high-risk category
    
    result["risk_score"] = min(risk_score, 100)  # Cap at 100
    
    # Add risk level text
    if result["risk_score"] >= 90:
        result["risk_level"] = "Critical"
    elif result["risk_score"] >= 75:
        result["risk_level"] = "High"
    elif result["risk_score"] >= 50:
        result["risk_level"] = "Medium"
    elif result["risk_score"] >= 25:
        result["risk_level"] = "Low"
    else:
        result["risk_level"] = "Minimal"
    
    # Cache the results
    cache_analysis(result)
    
    return result

def get_abuseipdb_data(ip):
    """Get detailed data from AbuseIPDB"""
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
        )
        if response.status_code == 200:
            return response.json()["data"]
        return None
    except Exception as e:
        print(f"Error fetching AbuseIPDB data: {e}")
        return None

def get_abuse_category_name(category_id):
    """Convert AbuseIPDB category ID to name"""
    categories = {
        1: "DNS Compromise",
        2: "DNS Poisoning",
        3: "Fraud Orders",
        4: "DDoS Attack",
        5: "FTP Brute-Force",
        6: "Ping of Death",
        7: "Phishing",
        8: "Fraud VoIP",
        9: "Open Proxy",
        10: "Web Spam",
        11: "Email Spam",
        12: "Blog Spam",
        13: "VPN IP",
        14: "Port Scan",
        15: "Hacking",
        16: "SQL Injection",
        17: "Spoofing",
        18: "Brute-Force",
        19: "Bad Web Bot",
        20: "Exploited Host",
        21: "Web App Attack",
        22: "SSH",
        23: "IoT Targeted"
    }
    return categories.get(category_id, f"Unknown ({category_id})")

def check_tor_exit_node(ip):
    """Check if the IP is a TOR exit node"""
    try:
        response = requests.get(f"https://check.torproject.org/torbulkexitlist")
        if response.status_code == 200:
            return ip in response.text.split('\n')
        return False
    except:
        return False

def get_ip_geolocation(ip):
    """Get geolocation data for an IP"""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        if response.status_code == 200:
            data = response.json()
            if data["status"] == "success":
                return {
                    "country": data.get("countryCode", ""),
                    "country_name": data.get("country", ""),
                    "city": data.get("city", ""),
                    "latitude": data.get("lat", ""),
                    "longitude": data.get("lon", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "as": data.get("as", "")
                }
        return None
    except:
        return None

def get_ip_history(ip):
    """Get historical data about an IP from our logs"""
    history = []
    
    # Check authentication logs
    if os.path.exists("logs/access.log"):
        with open("logs/access.log") as f:
            for line in f:
                if ip in line:
                    try:
                        entry = json.loads(line.strip())
                        history.append({
                            "time": entry.get("time", "unknown"),
                            "type": "login_attempt",
                            "status": entry.get("status", "unknown"),
                            "username": entry.get("user", "unknown")
                        })
                    except:
                        pass
    
    # Check honeypot logs
    if os.path.exists("logs/honeypot/access.log"):
        with open("logs/honeypot/access.log") as f:
            for line in f:
                if ip in line:
                    try:
                        entry = json.loads(line.strip())
                        history.append({
                            "time": entry.get("time", "unknown"),
                            "type": "honeypot_hit",
                            "honeypot": entry.get("honeypot", "unknown"),
                            "method": entry.get("method", "unknown")
                        })
                    except:
                        pass
    
    # Sort by time
    history.sort(key=lambda x: x.get("time", ""), reverse=True)
    return history

def get_cached_analysis(ip):
    """Get cached analysis result for an IP"""
    if not os.path.exists(f"{CACHE_DIR}/{ip}.json"):
        return None
    
    try:
        with open(f"{CACHE_DIR}/{ip}.json", "r") as f:
            return json.load(f)
    except:
        return None

def cache_analysis(result):
    """Cache the analysis result"""
    os.makedirs(CACHE_DIR, exist_ok=True)
    try:
        with open(f"{CACHE_DIR}/{result['ip']}.json", "w") as f:
            json.dump(result, f, indent=2)
    except Exception as e:
        print(f"Error caching analysis: {e}")

def batch_analyze_ips(ip_list):
    """Analyze multiple IPs at once"""
    results = {}
    for ip in ip_list:
        results[ip] = get_full_ip_analysis(ip)
    return results
