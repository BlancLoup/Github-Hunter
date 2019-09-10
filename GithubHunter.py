#!/usr/bin/python3
# -*- coding: utf-8 -*-

import configparser
import os
import re
import smtplib
import sqlite3
import sys
import traceback
from email import encoders
from email.header import Header
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, parseaddr
from time import gmtime, sleep, strftime

import requests
from lxml import etree
from lxml.html import tostring
from tqdm import tqdm


'''
Tool Name: GithubHunter
Author: Allen_Zhang
Main use: This tool is mainly to query the code that may be leaked in Github, user name, password, database information, network structure information, etc.
Implementation: After logging in to Github, search for keywords and then present the data
'''

def login_github(username,password):
    # Initialization parameters
    login_url = 'https://github.com/login'
    session_url = 'https://github.com/session'
    try:
        # Obtain session
        s = requests.session()
        resp = s.get(login_url).text
        dom_tree = etree.HTML(resp)
        key = dom_tree.xpath('//input[@name="authenticity_token"]/@value')
        user_data = {
            'commit': 'Sign in',
            'utf8': '✓',
            'authenticity_token': key,
            'login': username,
            'password': password
        }
        # Send data and log in
        s.post(session_url,data=user_data)
        s.get('https://github.com/settings/profile')
        return s
    except Exception as e:
        print('An exception occurred, please check the network settings and username and password')
        error_Record(str(e), traceback.format_exc())

def hunter(gUser, gPass, keywords):# Get the content you want to query based on the keyword

    print('''\033[1;34;0m     #####                                  #     #                                   
    #     # # ##### #    # #    # #####     #     # #    # #    # ##### ###### #####  
    #       #   #   #    # #    # #    #    #     # #    # ##   #   #   #      #    # 
    #  #### #   #   ###### #    # #####     ####### #    # # #  #   #   #####  #    # 
    #     # #   #   #    # #    # #    #    #     # #    # #  # #   #   #      #####  
    #     # #   #   #    # #    # #    #    #     # #    # #   ##   #   #      #   #  
     #####  #   #   #    #  ####  #####     #     #  ####  #    #   #   ###### #    #    V2.1 
                                                                                         Created by Allen   \r\n\r\n\033[0m''')

    global codes
    global tUrls
    try:
        # Code search
        s = login_github(gUser,gPass)
        print('Successful login, searching for leaked information.......')
        sleep(1)
        codes = []
        tUrls = []
        # Newly added 2 regular matches, the first matches the searched code portion; the second highlights the keyword
        pattern_code = re.compile(r'<div class="file-box blob-wrapper">(.*?)</div>', re.S)
        pattern_sub = re.compile(r'<em>', re.S)
        for keyword in keywords:
            for page in tqdm(range(1,7)):
                # Change the url of the search sorting method, include the url that may be leaked or use xpath to parse
                search_code = 'https://github.com/search?o=desc&p=' + str(page) + '&q=' + keyword +'&s=indexed&type=Code'
                resp = s.get(search_code)
                results_code = resp.text
                dom_tree_code = etree.HTML(results_code)
                # Get the link address where the information leaked
                Urls = dom_tree_code.xpath('//div[@class="flex-auto min-width-0 col-10"]/a[2]/@href')
                for url in Urls:
                    url = 'https://github.com' + url
                    tUrls.append(url)
                # Get the code part, first get the entire top DIV object containing the leaked code, then characterize the object, easy to use the regular to match the div part of the leaked code
                results = dom_tree_code.xpath('//div[@class="code-list-item col-12 py-4 code-list-item-public "]')
                for div in results:
                    result = etree.tostring(div, pretty_print=True, method="html")
                    code = str(result, encoding='utf-8')
                    # If there is a <div class="file-box blob-wrapper"> this tag matches the leaked key code part, it is empty if it doesn't exist.
                    if '<div class="file-box blob-wrapper">' in code:
                        data = pattern_code.findall(code)
                        codes.append(pattern_sub.sub('<em style="color:red">', data[0]))
                    else:
                        codes.append(' ')

        return tUrls, codes

    except Exception as e:
        # If an error occurs, write the file and print it out
        error_Record(str(e), traceback.format_exc())
        print(e)

def insert_DB(url, code):
    try:
        conn = sqlite3.connect('hunter.db')
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS Baseline (url varchar(1000) primary key, code varchar(10000))')
        cursor.execute('INSERT OR REPLACE INTO Baseline (url, code) values (?,?)', (url, code))
        cursor.close
        conn.commit()
        conn.close()
    except Exception as e:
        print("Database operation failed！\n")
        error_Record(str(e), traceback.format_exc())
        print(e)

def compare_DB_Url(url):
    try:
        con = sqlite3.connect('hunter.db')
        cur = con.cursor()
        cur.execute('SELECT url from Baseline where url = ?', (url,))
        results = cur.fetchall()
        cur.close()
        con.commit()
        con.close()
        return results
    except Exception as e:
        error_Record(str(e), traceback.format_exc())
        print(e)

def error_Record(error, tb):
    try:
        if os.path.exists('error.txt'):
            with open('error.txt', 'a', encoding='utf-8') as f:
                f.write(strftime("%a, %d %b %Y %H:%M:%S",gmtime()) + "-" + "Exception Record: " + error + '\n' + "The specific error message is as follows：\n" +tb + '\r\n')
        else:
            with open('error.txt', 'w', encoding='utf-8') as f:
                f.write(strftime("%a, %d %b %Y %H:%M:%S",gmtime()) + "-" + "Exception Record: " + error + '\n' + "The specific error message is as follows：\n" +tb + '\r\n')
    except Exception as e:
        print(e)

def send_mail(host, username, password, sender, receivers, message): 
    def _format_addr(s):
        name,addr = parseaddr(s)
        return formataddr((Header(name,'utf-8').encode(),addr))

    msg = MIMEText(message, 'html', 'utf-8')
    subject = 'Github information disclosure monitoring notice'
    msg['Subject'] = Header(subject, 'utf-8').encode()
    msg['From'] = _format_addr('Github information disclosure monitoring <%s>' % sender)
    msg['To'] = ','.join(receivers)
    try:
        smtp_obj = smtplib.SMTP(host, 25)
        smtp_obj.login(username, password)
        smtp_obj.sendmail(sender, receivers, msg.as_string())
        print('Mail sent successfully！')
        smtp_obj.close()
    except Exception as err:
        error_Record(str(err), traceback.format_exc())
        print(err)

if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read('info.ini')
    g_User = config['Github']['user']
    g_Pass = config['Github']['password']
    if config['OUTPUT']['output'] == 'stdout':
        out_to = 'stdout'
    elif config['OUTPUT']['output'] == 'email':
        # email params
        host = config['EMAIL']['host']
        m_User = config['EMAIL']['user']
        m_Pass = config['EMAIL']['password']
        m_sender = config['SENDER']['sender']
        receivers = []
        for k in config['RECEIVER']:
            receivers.append(config['RECEIVER'][k])
        out_to = 'email'
    else:
        if os.path.exists(config['OUTPUT']['output']):
            print("[!] File {} will be overwritten!".format(config['OUTPUT']['output']))
        elif os.access(os.path.dirname(config['OUTPUT']['output']), os.W_OK):
            print("[+] File {} will be created!".format(config['OUTPUT']['output']))
        else:
            print("[-] File location {} is not accessible! Exit.".format(config['OUTPUT']['output']))
            sys.exit(0)
            
        out_to = config['OUTPUT']['output']
    # Combination keyword，keyword + payload, join between the two “+” number, in accordance with Github search syntax
    keywords = []
    for keyword in config['KEYWORD']:
        for payload in config['PAYLOADS']:
            keywords.append(config['KEYWORD'][keyword] + '+' + config['PAYLOADS'][payload])

    message = 'Dear all<br><br>No new sensitive information found！'
    tUrls, codes= hunter(g_User, g_Pass, keywords)
    target_codes = []
    # The first run will find if there is a data file, if it does not exist, it will be newly created, if it exists, it will find a new item.
    if os.path.exists('hunter.db'):
        print("Database file exists for new data lookup......")
        # Split the keywords, look up the keywords and payload in the leaked code. If both exist, proceed to the next database lookup
        for keyword in keywords:
            payload = keyword.split('+')
            for i in range(0, len(tUrls)):
                if (payload[0] in codes[i]) and (payload[1] in codes[i]):
                    # If the value returned in the database is empty, it means that the entry does not exist in the database, 
                    # then the user added to target_codes sends the message and adds it to the database.
                    if not compare_DB_Url(tUrls[i]):
                        target_codes.append('<br><br><br>' + 'link：' + tUrls[i] + '<br><br>')
                        target_codes.append('The brief code is as follows：<br><div style="border:1px solid #bfd1eb;background:#f3faff">' + codes[i] + '</div>')
                        insert_DB(tUrls[i], codes[i])
    else:
        print("Database file not found, create and establish baseline......")
        for keyword in keywords:
            payload = keyword.split('+')
            for i in range(0, len(tUrls)):
                # Keywords and payloads are added to target_codes and written to the database.
                if (payload[0] in codes[i]) and (payload[1] in codes[i]):
                    target_codes.append('<br><br><br>' + 'link：' +tUrls[i] + '<br><br>')
                    target_codes.append('The brief code is as follows：<br><div style="border:1px solid #bfd1eb;background:#f3faff">' + codes[i] + '</div>')
                    insert_DB(tUrls[i], codes[i])
    # Mail alert when target_codes has data                
    if target_codes:
        warning = ''.join(target_codes)
        result = 'Dear all<br><br>Found information leaked! ' + 'Found a total of {}'.format(int(len(target_codes)/2)) + warning
    else: result = message
    if out_to == 'email':
        send_mail(host, m_User, m_Pass, m_sender, receivers, result)
    else:
        plain_result = re.sub(r'<.+?>', '', re.sub(r'<br>', "\n", result))
        if out_to == 'stdout': print(plain_result)
        else:
            if os.path.exists(out_to): os.remove(out_to)
            with open(out_to,'w+',encoding = "utf-8") as f: f.write(plain_result)
            print("[+] Result was written to {}!".format(out_to))
