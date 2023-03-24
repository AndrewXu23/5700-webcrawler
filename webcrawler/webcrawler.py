#!/usr/bin/env python3

import cgi
import socket
import sys
import ssl
from collections import deque
from html.parser import HTMLParser

# use a dara structure to track unique URLs already crawled
queued_pages = deque()
# use a dara structure to track URLs to be crawled
crawled_pages = deque()
# use a dara structure to store unique secret flags found in the pages
flags = []
# use a dara structure to hold the middlewaretoken
csrf_token = None
session_id = None

CRLF = "\r\n\r\n"


class FakebookHTMLParser(HTMLParser):
    """
    The FakebookHTMLParser extends the HTML Parser to parse through the server response for tags in search of
    more URLs and/or secret flags respectively.
    
    You can write code for the following tasks

    - look for the links in the HTML code that you will need to crawl, next.
    - look for the secret flags among tags, and process them
    - look for the csrfmiddlewaretoken, and process it.
    """
    def handle_starttag(self, tag, attrs):
        global queued_pages
        global csrf_token
        global flags

        if tag == 'a':
            for attrType, attrValue in attrs:
                if attrType == 'href' and attrValue not in queued_pages:
                    queued_pages.append(attrValue)
        elif tag == 'input':
            input_attrs = dict(attrs)
            if 'type' in input_attrs and input_attrs['type'] == 'hidden':
                if 'name' in input_attrs and input_attrs['name'] == 'csrfmiddlewaretoken':
                    csrf_token = input_attrs['value']
        elif tag == 'h2':
            for attrType, attrValue in attrs:
                if attrType == 'class' and attrValue == 'secret_flag':
                    flag = self.rawdata[self.getpos()[0]:self.getpos()[1]].strip()
                    flags.append(flag)

    # def handle_data(self, data):
    #     global flags

    #     if "FLAG: " in data:
    #         secret_flag = data.split(": ")[1]
    #         flags.append(secret_flag)



# Pareses http response
def parse_http_response(data):
    responseDict = {}
    data = data.split(CRLF)
    header = filter(None, data[0].split("\r\n"))

    body = data[1] if len(data) > 1 else ""
    status = header[0].split(" ")[1]

    responseDict["Status"] = status
    responseDict["Body"] = body

    for x in range(1, len(header)):
        pair = header[x].split(": ")
        if pair[0] in responseDict:
            responseDict[pair[0]] += "| " + pair[1]
        else:
            responseDict[pair[0]] = pair[1]
    return responseDict



#Parses the command line arguments for username and password. Throws error for invalid info
def parse_cmd_line():
   
    username = ""
    password = ""

    try:
        username = sys.argv[1]
        password = sys.argv[2]
        return username, password

    except:
        if username == "":
            sys.exit("Please provide appropriate user name.")
        if password == "":
            sys.exit("Please provide appropriate password.")


def create_socket():
    """Creates a TLS wrapped socket to create a connection to http server. """
    port = 443
    host_name = 'project2.5700.network'

    # building connection
    try:
        context = ssl.create_default_context()
        sock = socket.create_connection((host_name, port))
        wrapped_socket = context.wrap_socket(sock, server_hostname='project2.5700.network')
        return wrapped_socket
    except socket.error:
        sys.exit("Connection error.")

# Helper function to generate a cookie string to be sent in cookie field
def get_cookie_string(session_cookie=None, csrf_cookie=None):
    string = ""
    if csrf_cookie:
        if session_cookie:
            string = "csrftoken=%s; sessionid=%s" % (csrf_cookie, session_cookie)
        else:
            string = "csrftoken=%s" % (csrf_cookie)
    elif session_cookie:
        string = "sessionid=%s" % (session_cookie)
    return string


# this function will help you send the get request
def send_get_request(path, sock, host, cookie1=None, cookie2=None):
    """
    write code to send request along with appropriate header fields, and handle cookies. Send this header
    file to the server using socket
    """
    cookies = "Cookie:" + get_cookie_string(cookie1, cookie2)

    headers = "GET %s HTTP/1.1\r\nHost: %s\r\n%s\r\n" % (path, host, cookies)

    sock.send(headers.encode())

# this function will help you to receive message from the server for any request sent by the client
def receive_msg(sock):
    """
    Receive the message in a loop based on the content length given in the header
    Return received message
    """
    msg = ""
    while True:
        data = sock.recv(1024)
        if not data:
            break
        msg += data.decode("utf-8")
        if "\r\n\r\n" in msg:
            break
    return msg

    
def getContent_length(msg):

    """Extracts the content length of the URL"""    
    try:
        content_length = int(msg.split("Content-Length: ")[1].split("\r\n")[0])
    except:
        content_length = None
    return content_length


# this function will help you to extract cookies from the response message
def cookie_jar(msg):
    """
    Stores the session and/or the csrf cookies
    return cookies
    """
    cookies = {}
    for header in msg.split("\r\n"):
        if "Set-Cookie:" in header:
            if "sessionid" in header:
                cookie = header.split("sessionid=")[1].split(";")[0]
                cookeis["session"] = cookie
            elif "csrftoken" in header:
                cookie = header.split("csrftoken")[1].split(";")[0]
                cookies["csrftoken"] = cookie
    return cookies



#this function will help you to send the  request to login
def login_user(sock, path, host, body_len, body, cookie1, cookie2):
   """
   create a  request and send it to login to the fakebook site
   """
   # create the login request msg
   topMsg = "POST %s HTTP/1.1\r\nHost: %s\r\nConnection: close" % (path, host)
   contentType = "Content-Type: application/x-www-form-urlencoded"
   contentLen = "Content-Length: %s" % (body_len)
   cookies = "Cookie:" + get_cookie_string(cookie1, cookie2)
   
   request = topMsg + "\r\n" + contentType + "\r\n" + contentLen + "\r\n" + cookies + "\r\n" + body + "\r\n"
   
   # send the login request and receive the response
   soeck.send(request.encode())
   response = receive_msg(sock)
   
   # extract and save the session and csrf cookies
   cookies = cookie_jar(response)
   session_id = cookies.get("session")
   csrf_token = cookies.get("csrftoken")
   return


def start_crawling(msg, sock, host, cookie3, cookie4):
    """
    Implements the basic web crawler for this program.
    You can use the HTML Parser object to parse through the current URL in search for more URLs and/or secret flags until all
    secret flags are found for the user.
    Also accounts for and appropriately handles different errors received when parsing through pages.
    """
    global queued_pages, crawled_pages, flags, csrf_token, session_id

    # create a new parser object
    parser = FakebookHTMLParser()
    
    # add the first url to queue
    root_page_url = "http://project2.5700.network"
    queued_pages.append(root_page_url)

    # while len(queued_pages) > 0:
    #     next_page_url = queued_pages.popleft()

    #     try:





def main():
    host = "project2.5700.network"
    root_path = "/"
    fakebook_path = "/fakebook/"
    login_path = "/accounts/login/?next=/fakebook/"

    """  
    You can follow the following setps

    # Parse the username and password from the command line
    # Create TLS wrapped socket
    # get the root page
    # check the received message
    # store session cookie
    # send get request for login page
    # check message for login page
    # retrieving csrf cookie and middleware token
    # creating login body for user
    # login user
    # store new cookies
    # send request to go to my fakebook page
    # start your crawler
    # close the socket - program end
    
    """
    # Parse the username and password from the command line
    username, password = parse_cmd_line(username, password)
    
    # Create TLS wrapped socket
    wrapped_socket = create_socket()

    # get the root page
    send_get_request(root_path, wrapped_socket, host)

    # check the received message
    root_msg = receive_msg(wrapped_socket)
    if "200 OK" not in root_msg:
        print("Failed to get root page")
        return
    
    # store session cookie
    cookies = cookie_jar(root_msg)
    session_id = cookies["session"]

    # send get request for login page
    send_get_request(login_path, wrapped_socket, host)
    login_msg = receive_msg(wrapped_socket)

    # check message for login page
    if "200 OK" not in login_msg:
        print("Failed to get login page")
        return 

    # retrieving csrf cookie and middleware token
    cookies = cookie_jar(login_msg)
    csrf_token = cookies["csrftoken"]   # middleware token only use once in login request

    # creating login body for user
    login_body = {
        "username": username,
        "password": password,
        "csrfmiddlewaretoken": csrf_token
    }
    login_body_len = str(len(login_body))

    # login user and store new cookies to session_id and csrf_token
    login_user(sock, login_path, host, login_body_len, login_body, session_id, csrf_token)

    # send request to go to my fakebook page
    send_get_request(fakebook_path, wrapped_socket, host)
    fakebook_msg = receive_msg(wrapped_socket)

    # start your crawler

    # close the socket - program end
    wrapped_socket.close()


if __name__ == "__main__":
    main()
