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

def find_status_code(response):
    """
    Parses the HTTP response (given) and grabs the
    status code and returns it.
    :param response: String - the HTTP response to parse
    :return: Integer - the Status code
    """
    first_line = response.split('\n', 1)[0]
    if len(first_line):
        code = first_line[9:12]
    else:
        code = 500
    return int(code)

# Helper function to generate a cookie string to be sent in cookie field
def get_cookie_string(csrf_cookie=None, session_cookie=None):
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
    # cookies = "Cookie:" + get_cookie_string(cookie1, cookie2)
    cookies = get_cookie_string(cookie1, cookie2)
    if not cookies:
        headers = "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (path, host)
    else:
        headers = "GET %s HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\n\r\n" % (path, host, cookies)

    sock.send(headers.encode())


# this function will help you to receive message from the server for any request sent by the client
def receive_msg(sock):
    """
    Receive the message in a loop based on the content length given in the header
    Return received message
    """
    msg = sock.recv(4096).decode()
    length = getContent_length(msg)
    
    # print("contetn length " + str(length))
    
    while True:
        try:
            if length == None or length == 0:
                break
            elif not msg.endswith("</html>\n"):
                msg += sock.recv(4096).decode()
            else:
                break
        except: 
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
    sessionid = None
    csrftoken = None
    for header in msg.split("\r\n"):
        if "Set-Cookie:" in header:
            if "sessionid" in header:
                sessionid = header.split("sessionid=")[1].split(";")[0]
            elif "csrftoken" in header:
                csrftoken = header.split("csrftoken=")[1].split(";")[0]

    return sessionid, csrftoken



#this function will help you to send the  request to login
def login_user(sock, path, host, body_len, body, cookie1, cookie2):
   """
   create a  request and send it to login to the fakebook site
   """
   cookies_str = get_cookie_string(cookie1, cookie2)

   # create the login request msg
   topMsg = "POST %s HTTP/1.1\r\nHost: %s" % (path, host)
   contentType = "Content-Type: application/x-www-form-urlencoded"
   contentLen = "Content-Length: %d" % (body_len)
   cookies = "Cookie: %s" % (cookies_str)
   
   request = topMsg + "\r\n" + contentType + "\r\n" + contentLen + "\r\n" + cookies + CRLF + body
   
   # send the login request and receive the response
   sock.send(request.encode())
   response = receive_msg(sock)

   return response


def start_crawling(msg, sock, host, cookie3, cookie4):
    """
    Implements the basic web crawler for this program.
    You can use the HTML Parser object to parse through the current URL in search for more URLs and/or secret flags until all
    secret flags are found for the user.
    Also accounts for and appropriately handles different errors received when parsing through pages.
    msg: http response msg
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


    """
    #Zihan's solution:
    while len(queued_pages) > 0:
        # get the next url to crawl
        url = queued_pages.pop(0)

        # check if the url has already been crawled
        if url in crawled_pages:
            continue

        # send a GET request for the page
        send_get_request(url, sock, host, cookie3, cookie4)

        # receive the response
        response = receive_msg(sock)

        # parse the response for links and flags
        parser.feed(response)

        # add the url to the list of crawled pages
        crawled_pages.append(url)

    # return the list of found flags
    return flags
    
    """



def main():
    host = "project2.5700.network"
    root_path = "/"
    fakebook_path = "/fakebook/"
    login_path = "/accounts/login/?next=/fakebook/"

    # Parse the username and password from the command line
    username, password = parse_cmd_line()
    
    # Create TLS wrapped socket
    mysocket = create_socket()

    # get the root page
    send_get_request(root_path, mysocket, host)

    # check the received message
    root_msg = receive_msg(mysocket)
    root_status = find_status_code(root_msg)

    if root_status != 200:
        print("Failed to get root page")
        return
    
    # store session cookie
    # middleware token only use once in login request
    session_id, csrf_token = cookie_jar(root_msg)

    
    # send get request for login page
    send_get_request(login_path, mysocket, host, csrf_token, session_id)
    login_msg = receive_msg(mysocket)
    get_login_status = find_status_code(login_msg)

    # check message for login page
    if get_login_status != 200:
        print("Failed to get login page")
        return 

    # retrieving csrf cookie and middleware token
    session_id, csrf_token = cookie_jar(login_msg)


    # creating login body for user
    login_body = "username=%s&password=%s&csrfmiddlewaretoken=%s&next=" % (username, password, csrf_token)
    login_body_len = len(login_body)

    # login user 
    login_res = login_user(mysocket, login_path, host, login_body_len, login_body, csrf_token, session_id)
    login_status = find_status_code(login_res)
    
    # check login status
    if login_status != 302:
        print("Failed to login")
        return  

    # store new cookies to session_id and csrf_token
    session_id, csrf_token = cookie_jar(login_res)

    # send request to go to my fakebook page
    send_get_request(fakebook_path, mysocket, host, csrf_token, session_id)
    fakebook_msg = receive_msg(mysocket)
    fakebook_status = find_status_code(fakebook_msg)
    
    # check if get page successed
    if fakebook_status != 200:
        print("Failed to get fakebook page")
        return 

    # start your crawler

    # close the socket - program end
    mysocket.close()


if __name__ == "__main__":
    main()
