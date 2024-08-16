#!/usr/bin/env python3

import argparse
import requests
from scapy.all import sniff, IP
from selenium import webdriver
from pymediainfo import MediaInfo
import matplotlib.pyplot as plt
import time

# Function to monitor network traffic
def monitor_traffic(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f'IP src: {ip_layer.src} dst: {ip_layer.dst}')
        # Improve detection logic here, e.g., check for suspicious IPs
        if is_suspicious_ip(ip_layer.dst):
            return 1
    return 0

def is_suspicious_ip(ip):
    # Example logic to determine if an IP is suspicious
    suspicious_ips = ['192.168.1.1', '203.0.113.0']
    return ip in suspicious_ips

# Function to start network traffic monitoring
def start_network_monitoring(duration=10):
    print("Starting network monitoring...")
    suspicious_count = sniff(prn=monitor_traffic, timeout=duration).count(1)
    print("Network monitoring finished.")
    return suspicious_count

# Function to monitor browser activity and check for cookies
def monitor_cookies():
    driver = webdriver.Firefox()
    driver.get('https://example.com')
    cookies = driver.get_cookies()
    tracker_count = 0
    for cookie in cookies:
        print(f"Cookie: {cookie['name']} - Domain: {cookie['domain']}")
        if 'tracker' in cookie['name'].lower() or is_known_tracker(cookie['domain']):
            tracker_count += 1
    driver.quit()
    return tracker_count

def is_known_tracker(domain):
    known_trackers = ['doubleclick.net', 'google-analytics.com']
    return any(tracker in domain for tracker in known_trackers)

# Function to analyze metadata of a file
def analyze_metadata(file_path):
    media_info = MediaInfo.parse(file_path)
    metadata_exposure = 0
    for track in media_info.tracks:
        print(track.to_data())
        if 'location' in track.to_data().lower() or 'gps' in track.to_data().lower():
            metadata_exposure += 2  # Higher weight for sensitive metadata
        else:
            metadata_exposure += 1
    return metadata_exposure

# Function to check Google account activity
def check_google_activity(token):
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get('https://www.googleapis.com/userinfo/v2/me', headers=headers)
    account_activity = response.json()
    # Improve logic to detect suspicious activity
    unusual_logins = detect_unusual_logins(account_activity)
    return unusual_logins

def detect_unusual_logins(account_activity):
    unusual_count = 0
    # Example logic for detecting unusual logins
    for activity in account_activity.get('logins', []):
        if activity['location'] not in ['expected_location1', 'expected_location2']:
            unusual_count += 1
        if activity['time'].hour < 6 or activity['time'].hour > 22:
            unusual_count += 1
    return unusual_count

# Improved Surveillance Score Calculation
def calculate_surveillance_score(network_issues, tracker_count, metadata_exposure, account_activity):
    # Detailed calculation with thresholds and weights
    network_score = min(network_issues, 10) * 4  # Cap network issues at 10 for scoring
    tracker_score = min(tracker_count, 10) * 3
    metadata_score = min(metadata_exposure, 10) * 2
    activity_score = min(account_activity, 10) * 1
    
    total_score = network_score + tracker_score + metadata_score + activity_score
    max_score = 100  # 40 (network) + 30 (trackers) + 20 (metadata) + 10 (activity)
    
    return (total_score / max_score) * 100

# Function to plot surveillance score over time
def plot_surveillance_score(scores):
    plt.plot(scores)
    plt.xlabel('Time')
    plt.ylabel('Surveillance Score')
    plt.title('Surveillance Score Over Time')
    plt.show()

# Main function to run the surveillance detection
def main(token, file_path, iterations, duration):
    scores = []

    for _ in range(iterations):
        print("Iteration started...")
        
        # Network monitoring
        network_issues = start_network_monitoring(duration=duration)

        # Browser activity monitoring
        tracker_count = monitor_cookies()

        # Metadata analysis
        metadata_exposure = analyze_metadata(file_path)

        # Account activity logging
        account_activity = check_google_activity(token)

        # Calculate improved surveillance score
        score = calculate_surveillance_score(network_issues, tracker_count, metadata_exposure, account_activity)
        print(f'Surveillance Score: {score}')
        scores.append(score)

        time.sleep(60)  # Wait for 1 minute before next iteration

    # Plot surveillance score over time
    plot_surveillance_score(scores)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Surveillance Detection Script")
    parser.add_argument("--token", type=str, required=True, help="OAuth token for Google API")
    parser.add_argument("--file_path", type=str, required=True, help="Path to the file for metadata analysis")
    parser.add_argument("--iterations", type=int, default=5, help="Number of iterations to run")
    parser.add_argument("--duration", type=int, default=10, help="Duration of network monitoring in seconds")

    args = parser.parse_args()
    
    main(args.token, args.file_path, args.iterations, args.duration)
