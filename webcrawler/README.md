











6. def send_get_request(path, sock, host, cookie1=None, cookie2=None):

send a GET request to a specified path on a server using a socket connection. It takes several arguments, including path, sock, host, and optional cookie1 and cookie2 parameters for handling cookies. It first calls the get_cookie_string() function to retrieve a cookie string based on the provided cookie parameters. If no cookies are specified, the headers variable is set to a basic HTTP request header with the path and host fields. If cookies are specified, the headers variable is set to include a Cookie field with the cookie string appended to the basic HTTP request header.
Finally, the function sends the resulting headers string to the server using the socket connection.


7. def receive_msg(sock):

To receive a message from a server over a socket connection. The function takes socket object used for the connection.The function starts by receiving a chunk of data from the server using the recv() method on the socket object. The size of the data chunk is set to 4096 bytes.
Next, the function calls the getContent_length() function to extract the content length from the received message. If no content length is found, the function exits the loop and returns the message. If a content length is found, the function enters a loop where it receives additional chunks of data from the server until the length of the received message matches the content length specified in the header. The loop also checks to see if the message ends with the </html> tag. If it does, the loop is exited and the full message is returned.(getContent_length() function may not correctly extracting the content length and then cause the error)

8. def getContent_length(msg):
To extract the content length from an HTTP response message received from a server. The function takes msg, which represents the HTTP response message. The function starts by using the split() method to split the message string into an array based on the "Content-Length:" header field. It then extracts the second element of the resulting array (which should contain the content length) using another split() method call. Next, the function converts the extracted content length string to an integer using the int() function. If any errors occur during this process (such as if the message does not contain a valid content length header), the function sets the content_length variable to None.
Finally, the function returns the extracted content length value.

9. def cookie_jar(msg):
To extract cookies from an HTTP response message received from a server. The function starts by initializing two variables, sessionid and csrftoken, to None. These variables will be used to store the values of any session ID or CSRF token cookies that are found in the response message.
The function then iterates over each header line in the response message, using the split() method to split the message into an array based on the "\r\n" line delimiter. For each header line, the function checks if the "Set-Cookie:" header is present using the in keyword. If a cookie header is found, the function checks if the header contains the session ID or CSRF token cookie by checking for the presence of the respective cookie name ("sessionid" or "csrftoken") using the in keyword. If the cookie is found, the function extracts the value of the cookie from the header using the split() method and stores it in the appropriate variable.
Finally, the function returns a tuple containing the values of the sessionid and csrftoken variables.


10. def login_user(sock, path, host, body_len, body, cookie1, cookie2):
This function sends a POST request with the user's login credentials to the specified path on the specified host. The request includes the content type and length, as well as any cookies provided. The function then waits for a response from the server and returns it.
Potential errors in this function could include issues with the request message construction, such as incorrect formatting of the headers or body. It could also encounter issues if the server is down or if the login credentials are incorrect.



11. def start_crawling(msg, sock, host, cookie3, cookie4):
This function starts by creating a FakebookHTMLParser object to parse the HTML of each page. It then adds the root page URL to the queue of pages to be crawled.
The function then enters a loop, where it gets the next URL to crawl from the front of the queue. If the URL has already been crawled, it skips it. Otherwise, it sends a GET request to the URL, receives the response, and parses it for links and flags using the FakebookHTMLParser object.
The function then adds the current URL to the list of crawled pages and repeats the loop until there are no more pages in the queue. Finally, it returns the list of found flags.
