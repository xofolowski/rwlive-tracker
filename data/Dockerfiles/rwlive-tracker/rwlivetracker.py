#!/usr/bin/env python3
import requests
import sys
import sqlite3
import json
import schedule
import time
import argparse
from datetime import datetime
from fuzzywuzzy import fuzz
import smtplib
from email.mime.text import MIMEText
from urllib.parse import urlparse

DATABASE = '/rwlive-tracker/data/ransomware_data.db'

# Function to initialize the database with additional tables
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS victims (
            published TEXT PRIMARY KEY,
            activity TEXT,
            country TEXT,
            description TEXT,
            discovered TEXT,
            group_name TEXT,
            infostealer TEXT,
            post_title TEXT,
            post_url TEXT,
            screenshot TEXT,
            domain TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            recipient_list TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            keyword VARCHAR UNIQUE,
            FOREIGN KEY (customer_id) REFERENCES customers (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS historical_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            published TEXT,
            keyword TEXT,
            customer_id INTEGER,
            FOREIGN KEY (customer_id) REFERENCES customers (id)
        )
    ''')
    conn.commit()
    conn.close()

# Function to extract domain from a URL
def extract_domain(url):
    parsed_url = urlparse(url)
    if parsed_url.netloc:
        return parsed_url.netloc
    else:
        return parsed_url.path.split("/")[0]
    
# Function to insert data into the database
def insert_data(data):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    for item in data:
        # Process website to extract only the domain
        domain = extract_domain(item.get('website', ''))
        infostealer_data = json.dumps(item.get('infostealer', {}))
        cursor.execute('''
            INSERT OR IGNORE INTO victims (
                published, activity, country, description, discovered,
                group_name, infostealer, post_title, post_url, screenshot, domain
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            item.get('published'),
            item.get('activity'),
            item.get('country'),
            item.get('description'),
            item.get('discovered'),
            item.get('group_name'),
            infostealer_data,
            item.get('post_title'),
            item.get('post_url'),
            item.get('screenshot'),
            domain  # Use extracted domain
        ))
    conn.commit()
    conn.close()

# Function to fetch and store initial dataset from a range of years
def fetch_initial_data(start_year):
    current_year = datetime.now().year
    for year in range(start_year, current_year + 1):
        url = f'https://api.ransomware.live/victims/{year}'
        print(f"Fetching data for year: {year}")
        data = fetch_data(url)
        insert_data(data)

# Function to fetch recent victims and perform fuzzy matching
def poll_recent_victims():
    recent_victims_url = 'https://api.ransomware.live/recentvictims'
    print("Polling /recentvictims")
    recent_data = fetch_data(recent_victims_url)
    print(recent_data[0])
    insert_data(recent_data)
    
    # Perform fuzzy matching and send emails
    process_matches()

# Function to perform fuzzy matching and send email notifications
def process_matches(notify=True):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Fetch all keywords and customers
    cursor.execute('SELECT * FROM keywords')
    keywords = cursor.fetchall()

    cursor.execute('SELECT * FROM customers')
    customers = cursor.fetchall()

    matches_summary = {}
    for customer in customers:
        customer_id, name, recipient_list = customer
        recipient_list = json.loads(recipient_list)
        customer_matches = []
        
        # Fetch customer-specific keywords
        cursor.execute('SELECT keyword FROM keywords WHERE customer_id = ?', (customer_id,))
        customer_keywords = [row[0] for row in cursor.fetchall()]
        
        # Fetch all victims data
        cursor.execute('SELECT published, post_title, domain, group_name, post_url FROM victims')
        victims = cursor.fetchall()
        
        # Perform fuzzy matching
        for keyword in customer_keywords:
            for victim in victims:
                published, post_title, domain, group_name, post_url = victim
                
                # Check if this match has been recorded
                cursor.execute('''
                    SELECT COUNT(*) FROM historical_matches
                    WHERE published = ? AND keyword = ? AND customer_id = ?
                ''', (published, keyword, customer_id))
                match_count = cursor.fetchone()[0]
                
                if match_count == 0:
                    if ((len(keyword) <= len(post_title) and 
                         fuzz.partial_ratio(keyword.lower(), post_title.lower()) == 100) or
                        fuzz.ratio(keyword.lower(), domain.lower()) == 100):
                        print(f"Match found: {post_title}")
                        customer_matches.append({
                            'published': published,
                            'post_title': post_title,
                            'domain': domain,
                            'group_name': group_name,
                            'post_url': post_url,
                            'keyword': keyword
                        })
                        # Record this match
                        cursor.execute('''
                            INSERT INTO historical_matches (published, keyword, customer_id)
                            VALUES (?, ?, ?)
                        ''', (published, keyword, customer_id))

        if customer_matches and notify:
            matches_summary[name] = customer_matches
            for recipient in recipient_list:
                send_email_notification(recipient, customer_matches)
    
    if matches_summary and notify:
        send_summary_to_admin(matches_summary)
    conn.commit()
    conn.close()

# Function to send email summary to admin
def send_summary_to_admin(matches_summary):
    with open(CONFIGFILE) as f:
        config = json.load(f)

    admin_email = config['admin_email']
    subject = "Ransomware Victim Matches Summary"
    body = "Summary of victim matches:\n\n"
    for customer, matches in matches_summary.items():
        body += f"+ Customer: {customer}\n\n"
        for match in matches:
            body += f"   - Keyword: {match['keyword']}\n"
            body += f"   - Published: {match['published']}\n"
            body += f"   - Post Title: {match['post_title']}\n"
            body += f"   - Domain: {match['domain']}\n"
            body += f"   - Group Name: {match['group_name']}\n"
            body += f"   - Post URL: {match['post_url']}\n"
            body += "\n\n"
        body += "="*40
        body += "\n\n"
    send_email(admin_email, subject, body)

# Function to send email notifications to individual customers
def send_email_notification(recipient, matches):
    subject = "New Ransomware Victim Matches"
    body = "You have new matches for your keywords:\n\n"
    for match in matches:
        body += f"Keyword: {match['keyword']}\n"
        body += f"Published: {match['published']}\n"
        body += f"Post Title: {match['post_title']}\n"
        body += f"Domain: {match['domain']}\n"
        body += f"Group Name: {match['group_name']}\n"
        body += f"Post URL: {match['post_url']}\n"
        body += "\n"
    send_email(recipient, subject, body)

# Function to send email
def send_email(to, subject, body):
    with open(CONFIGFILE) as f:
        config = json.load(f)

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = config['smtp_from']
    msg['To'] = to

    with smtplib.SMTP(config['smtp_server'], config['smtp_port']) as server:
        server.starttls()
        server.login(config['smtp_user'], config['smtp_password'])
        server.send_message(msg)

# Function to fetch data from the API
def fetch_data(url):
    response = requests.get(url)
    response.raise_for_status()  # Check for HTTP errors
    return response.json()

# Function to import customer data from JSON file
def import_customers(file_path):
    with open(file_path, 'r') as f:
        customers = json.load(f)
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    for customer in customers:
        cursor.execute('''
            INSERT OR IGNORE INTO customers (name, recipient_list)
            VALUES (?, ?)
        ''', (customer['name'], json.dumps(customer['recipient_list'])))
    conn.commit()
    conn.close()

# Function to import keywords for an existing customer from JSON file
def import_keywords(file_path, customer_id):
    with open(file_path, 'r') as f:
        keywords = json.load(f)
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    for keyword in keywords:
        cursor.execute('''
            INSERT OR IGNORE INTO keywords (customer_id, keyword)
            VALUES (?, ?)
        ''', (customer_id, keyword))
    conn.commit()
    conn.close()

# Function to list all customers and their keywords
def list_customers_keywords():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM customers')
    customers = cursor.fetchall()
    
    for customer in customers:
        customer_id, name, recipients = customer
        print(f"ID: {customer_id} -- Customer: {name} (Email recipients: {recipients})")
        
        cursor.execute('SELECT keyword FROM keywords WHERE customer_id = ?', (customer_id,))
        keywords = cursor.fetchall()
        for keyword in keywords:
            print(f"  Keyword: {keyword[0]}")
    
    conn.close()

# Function to list all historical matches without sending out alerts
def list_historical_matches():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT h.published, h.keyword, c.name
        FROM historical_matches h
        JOIN customers c ON h.customer_id = c.id
    ''')
    matches = cursor.fetchall()
    
    for match in matches:
        published, keyword, customer_name = match
        print(f"Published: {published}, Keyword: {keyword}, Customer: {customer_name}")
    
    conn.close()

# Main function to handle command-line arguments and execute tasks
def main(polling_interval, initialize, start_year, import_customers_file, import_keywords_file, customer_id, list_customers, list_matches, match_history):
    # we always initialize the DB to ensure it is there
    init_db()

    # Initially populate the database if requested
    if initialize:
        fetch_initial_data(start_year)
        sys.exit(0)
    
    # Import customer data if file provided
    if import_customers_file:
        import_customers(import_customers_file)
        sys.exit(0)
    
    # Import keywords if file and customer ID provided
    if import_keywords_file and customer_id:
        import_keywords(import_keywords_file, customer_id)
        sys.exit(0)
    
    # List customers and keywords if requested
    if list_customers:
        list_customers_keywords()
        sys.exit(0)
    
    # List historical matches if requested
    if match_history:
        process_matches(False)
        list_historical_matches()
        sys.exit(0)
    
    # List historical matches if requested
    if list_matches:
        list_historical_matches()
        sys.exit(0)
    
    # Schedule the periodic polling
    schedule.every(polling_interval).seconds.do(poll_recent_victims)

    # Run the scheduler
    print(f"Starting periodic polling every {polling_interval} seconds...")
    while True:
        schedule.run_pending()
        time.sleep(1)

# Command-line interface
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch and store ransomware data.")
    parser.add_argument('-c', '--config', type=str, default="/rwlive-tracker/conf/config.json",
                        help="Path to config file (default: /rwlive-tracker/conf/config.json).")
    parser.add_argument('-p', '--polling_interval', type=int, default=3600,
                        help="Polling interval in seconds (default: 3600).")
    parser.add_argument('-i', '--initialize', action='store_true',
                        help="Initialize the database and fetch initial data.")
    parser.add_argument('-s','--start_year', type=int, default=datetime.now().year,
                        help="Start year for fetching initial data (default: current year).")
    parser.add_argument('--import_customers', type=str,
                        help="Path to JSON file for importing customer data.")
    parser.add_argument('--import_keywords', type=str,
                        help="Path to JSON file for importing keywords.")
    parser.add_argument('--customer_id', type=int,
                        help="Customer ID for importing keywords.")
    parser.add_argument('--list_customers', action='store_true',
                        help="List all customers and their configured keywords.")
    parser.add_argument('--match_history', action='store_true',
                        help="Perform historical matching of all known keywords without sending out alerts.")
    parser.add_argument('--list_matches', action='store_true',
                        help="List all historical matches without sending out alerts.")
    args = parser.parse_args()

    CONFIGFILE=args.config
    main(args.polling_interval, args.initialize, args.start_year, args.import_customers, args.import_keywords, args.customer_id, args.list_customers, args.list_matches, args.match_history)
