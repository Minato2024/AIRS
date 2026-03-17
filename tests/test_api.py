import requests
import json
from datetime import datetime

# Test configuration
BASE_URL = "http://localhost:8000"

def test_health():
    """Test if API is running"""
    try:
        response = requests.get(f"{BASE_URL}/health")
        print(f"Health Check: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def send_honeypot_log():
    """Send a test Dionaea log"""
    
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "honeypot_type": "dionaea",
        "session_id": "test_session_001",
        "source_ip": "192.168.1.100",
        "source_port": 54321,
        "dest_port": 80,
        "protocol": "tcp",
        "event_type": "http_request",
        "username": None,
        "password": None,
        "command": None,
        "payload": None,
        "meta_data": {
            "http_method": "GET",
            "http_url": "http://evil.com/malware.exe?download=1",
            "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "http_host": "evil.com",
            "dionaea_file_type": "exe",
            "dionaea_file_size": 1024000,
            "connection_transport": "tcp"
        }
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/v1/honeypot/ingest",
            json=log_data,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"\nStatus Code: {response.status_code}")
        print(f"Response:\n{json.dumps(response.json(), indent=2)}")
        
        return response.json()
        
    except Exception as e:
        print(f"Error sending log: {e}")
        return None

def send_smb_attack():
    """Send an SMB-based attack log"""
    
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "honeypot_type": "dionaea",
        "session_id": "test_smb_001",
        "source_ip": "10.0.0.50",
        "source_port": 445,
        "dest_port": 445,
        "protocol": "tcp",
        "event_type": "smb_request",
        "meta_data": {
            "smb_command": "SMB_COM_TREE_CONNECT",
            "smb_share": "\\\\192.168.1.100\\ADMIN$",
            "smb_file": "\\\\192.168.1.100\\ADMIN$\\malware.exe",
            "smb_native_os": "Windows 10",
            "connection_transport": "tcp"
        }
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/v1/honeypot/ingest",
            json=log_data
        )
        
        print(f"\nSMB Attack - Status: {response.status_code}")
        print(json.dumps(response.json(), indent=2))
        return response.json()
        
    except Exception as e:
        print(f"Error: {e}")
        return None

def send_ftp_attack():
    """Send FTP brute force attempt"""
    
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "honeypot_type": "dionaea",
        "session_id": "test_ftp_001",
        "source_ip": "172.16.0.25",
        "source_port": 12345,
        "dest_port": 21,
        "protocol": "tcp",
        "event_type": "ftp_login",
        "username": "admin",
        "password": "password123",
        "meta_data": {
            "ftp_command": "RETR /etc/passwd",
            "ftp_arg": "/etc/passwd",
            "connection_transport": "tcp"
        }
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/v1/honeypot/ingest",
            json=log_data
        )
        
        print(f"\nFTP Attack - Status: {response.status_code}")
        print(json.dumps(response.json(), indent=2))
        return response.json()
        
    except Exception as e:
        print(f"Error: {e}")
        return None

def check_stats():
    """Get detection stats"""
    try:
        response = requests.get(f"{BASE_URL}/api/v1/detection/stats?hours=24")
        print(f"\nDetection Stats (24h):")
        print(json.dumps(response.json(), indent=2))
    except Exception as e:
        print(f"Error: {e}")

def check_dashboard():
    """Get dashboard stats"""
    try:
        response = requests.get(f"{BASE_URL}/api/v1/dashboard/stats")
        print(f"\nDashboard Stats:")
        print(json.dumps(response.json(), indent=2))
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("=" * 50)
    print("AIRS API Testing")
    print("=" * 50)
    
    # Check health first
    if not test_health():
        print("API is not running! Start it first with:")
        print("  cd app && uvicorn main:app --reload")
        exit(1)
    
    # Send test logs
    print("\n" + "=" * 50)
    print("Sending Test Logs...")
    print("=" * 50)
    
    # Test 1: HTTP/Malware
    print("\n>>> Test 1: HTTP Malware Download")
    result1 = send_honeypot_log()
    
    # Test 2: SMB Attack
    print("\n>>> Test 2: SMB File Share Attack")
    result2 = send_smb_attack()
    
    # Test 3: FTP Attack
    print("\n>>> Test 3: FTP Data Exfiltration")
    result3 = send_ftp_attack()
    
    # Check stats
    print("\n" + "=" * 50)
    print("Checking System Stats...")
    print("=" * 50)
    check_stats()
    check_dashboard()
    
    print("\n" + "=" * 50)
    print("Testing Complete!")
    print("=" * 50)