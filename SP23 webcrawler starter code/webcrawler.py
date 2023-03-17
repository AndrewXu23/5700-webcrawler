#!/usr/bin/env python3

import cgi
import socket
import sys
import ssl
from collections import deque
from html.parser import HTMLParser

# use a dara structure to track unique URLs already crawled

# use a dara structure to track URLs to be crawled

# use a dara structure to store unique secret flags found in the pages

# use a dara structure to hold the middlewaretoken



class FakebookHTMLParser(HTMLParser):
    """
    The FakebookHTMLParser extends the HTML Parser to parse through the server response for tags in search of
    more URLs and/or secret flags respectively.
    
    You can write code for the following tasks

    - look for the links in the HTML code that you will need to crawl, next.

    - look for the secret flags among tags, and process tham

    - look for the csrfmiddlewaretoken, and process it.
    """
    

    
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


# this function will help you send the get request
def send_get_request(path, sock, host, cookie1=None, cookie2=None):
    """
    write code to send request along with appropriate header fields, and handle cookies. Send this header
    file to the server using socket

    """

# this function will help you to receive message from the server for any request sent by the client

def receive_msg(sock):
    """
    
    Receive the message in a loop based on the content length given in the header
    
    
    """
    
def getContent_length(msg):

    """Extracts the content length of the URL"""    
    


# this function will help you to extract cookies from the response message
def cookie_jar(msg):
    """

   
    Stores the session and/or the csrf cookies

    return cookies
    
    """
    




#this function will help you to send the  request to login
def login_user(sock, path, host, body_len, body, cookie1, cookie2):
   """
   create a  request and send it to login to the fakebook site
   """


def start_crawling(msg, sock, host, cookie3, cookie4):
    """
    Implements the basic web crawler for this program.
    You can use the HTML Parser object to parse through the current URL in search for more URLs and/or secret flags until all
    secret flags are found for the user.
    Also accounts for and appropriately handles different errors received when parsing through pages.
    """
    




def main():
    host = "Host: project2.5700.network"
    root_path = "/"
    fakebook = "/fakebook/"
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

    
    


if __name__ == "__main__":
    main()
