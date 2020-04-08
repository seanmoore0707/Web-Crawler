/** COMP30023 Project1
* Haonan Chen, ID: 930614 
* Email: haonanc1@student.unimelb.edu.au
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <regex.h>
#include <ctype.h>
#include "include/map.h"
#include "include/gumbo.h"
#include "include/vec.h"

/* Constants */
#define MAX_PAGE_NUM 100
#define MAX_CONTENT_LEN 100000
#define MAX_URL_LEN 1000
#define USER_NAME "haonanc1"
#define CREDENTIAL "aGFvbmFuYzE6cGFzc3dvcmQ="
#define MIME_TYPE "text/html"
#define PORT "80"
// Regex pattern to decouple URL components.
#define URL_PATTERN "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?"
// Regex pattern to match URL encoding pattern "%XY".
#define URL_ENCODING "(%[0-9A-Fa-f]{2}$)+"
#define HEADER_SPLIT "\r\n"
#define EMPTY_LINE "\r\n\r\n"
#define SCHEME "http://"
#define HTTP_TAG "http"
#define STATUS_SUCCESS 200
#define STATUS_UNAUTHORIZED 401
#define STATUS_PAGE_NOT_FOUND 404
#define STATUS_GONE 410
#define STATUS_URI_TOO_LONG 414
#define STATUS_MOVE_PERMANENTLY 301
#define STATUS_SERVICE_UNAVAILABLE 503
#define STATUS_GATEWAY_TIMEOUT 504


/*Global variables*/
// The format for normal requests.
static char * format = "GET %s HTTP/1.1\r\n\
Host: %s\r\n\
User-Agent: %s\r\n\
Connection: close\r\n\
Accept: %s\r\n\r\n";
// The format for requests when dealing with status code 401, need to add the authorization header.
static char * auth_format = "GET %s HTTP/1.1\r\n\
Host: %s\r\n\
User-Agent: %s\r\n\
Connection: close\r\n\
Authorization: Basic %s\r\n\
Accept: %s\r\n\r\n";

/* The buffer to save the information of HTML page*/
static char buffer[MAX_CONTENT_LEN+1];
int numOfURL = 0;
char* retry = NULL;


// Struct to decouple each component of URL.
struct params {
    char* host;
    char* path;
    char* port;
    char* scheme;
};



// Since the URL is partially case sensitive (case sensitive in path), we need to transfer the scheme and host to lowercase.
// flag == 1 indicates we need to convert string to lower cases.
static void slice_str(const char * source, char * dest, size_t start, size_t end, int flag)
{
    size_t j = 0;
    for ( size_t i = start; i < end; ++i ) {
        if(flag==1){
        dest[j] = tolower(source[i]);}
        else{
        dest[j] = source[i];   
        }
        j+=1;
    }
    // Need to add null character at the end of string.
    dest[j] = '\0';
}

// Check the length of URL and whether the URL contains special symbols.
static int isValid(char* url){
    
    if(strlen(url) > MAX_URL_LEN) return 0;

    if(strstr(url, "/.")!= NULL || strstr(url, "./")!= NULL || strstr(url, "..")!= NULL\
     || strstr(url, "?")!= NULL || strstr(url, "#")!= NULL ) return 0;
    
    regex_t compiled;

    if (regcomp(&compiled, URL_ENCODING, REG_EXTENDED) != 0)
    {
        fprintf(stderr, "Failed to compile regex '%s'\n", URL_PATTERN);
        exit(EXIT_FAILURE);
    }

    int nsub = compiled.re_nsub;

    regmatch_t matchptr[nsub];

    int err = regexec(&compiled, url, nsub, matchptr, 0);

    if(err == 0){
        return 0;
    }else if(err == REG_ESPACE){
        fprintf(stderr,"Ran out of memory.\n");
        return 0;
    }

    regfree(&compiled);
    return 1;

}

// Decouple the URL to host, path, scheme components.
static void getParams(char* url, struct params* result){
    regex_t compiled;
    result->host = NULL;
    result->path = NULL;
    result->port = NULL;
    result->scheme = NULL;

    if (regcomp(&compiled, URL_PATTERN, REG_EXTENDED) != 0)
    {
        fprintf(stderr, "Failed to compile regex '%s'\n", URL_PATTERN);
        exit(EXIT_FAILURE);
    }

    int nsub = compiled.re_nsub;

    regmatch_t matchptr[nsub];
    
    int err =regexec(&compiled, url, nsub, matchptr, 0);


    if(err == REG_NOMATCH){
        fprintf(stderr,"Regular expression did not match.\n");
    }else if(err == REG_ESPACE){
        fprintf(stderr,"Ran out of memory.\n");
    }
  

    /** In regmatch_t, we can determine the value of the five components as
    *  scheme    = $2
    *   authority(hostname) = $4
    *   path      = $5
    *   query     = $7
    *   fragment  = $9
    */
    int pathlen = matchptr[5].rm_eo - matchptr[5].rm_so;
    int hostlen = matchptr[4].rm_eo - matchptr[4].rm_so;
    int schemelen = matchptr[2].rm_eo - matchptr[2].rm_so;

    result->scheme = (char*)malloc(sizeof(char) * (schemelen+1));
    slice_str(url, result->scheme, matchptr[2].rm_so, matchptr[2].rm_eo,1);


    char* temp = (char*)malloc(sizeof(char) * (hostlen+1));
    slice_str(url, temp, matchptr[4].rm_so, matchptr[4].rm_eo,1);

    /** Check whether the port number is in the "authority" part, since in this project we only consider port 80, 
    * therefore we can only need to extract hostname, ignore port number. However, for the extensibility of the program, 
    * I manage to extract the port number for futher use, although it seems redundant for this project.
    */
    if (strstr(temp, ":") != NULL){
        char* symbol = strstr(temp, ":");
        int pos = (int) (symbol - temp);
        result->host = (char*)malloc(sizeof(char) * (pos+1));
        result->port = (char*)malloc(sizeof(char) * (strlen(temp) -1 - pos));
        slice_str(temp, result->host, 0, pos,0);
        slice_str(temp, result->port, pos+1, strlen(temp),0);

        if(strlen(result->port)!= strlen(PORT)|| memcmp(result->port, PORT, strlen(PORT))!=0){
            free(result->port);
            result->port = (char*)malloc(sizeof(char) * strlen(PORT));
            result->port = PORT;
        }
    }
    else{
        result->host = (char*)malloc(sizeof(char) * (hostlen+1));
        result->port = (char*)malloc(sizeof(char) * strlen(PORT));
        result->port = PORT;
        slice_str(url, result->host, matchptr[4].rm_so, matchptr[4].rm_eo,1);
    }

    if(pathlen == 0){
        result->path = (char*)malloc(sizeof(char) * 2);
        result->path[0] = '/';
        result->path[1] = '\0';
    }
    else{

        result->path = (char*)malloc(sizeof(char) * (pathlen + 1));
        slice_str(url, result->path, matchptr[5].rm_so, matchptr[5].rm_eo,0);

    // Handle with situation that path doesn't start with '/'
    if(result->path[0]!='/'){
        int l = strlen(result->path);
        char* temp_path1 = (char*)malloc(sizeof(char) * (l+1));
        slice_str(result->path, temp_path1, 0, strlen(result->path), 0);
        result->path = (char*)malloc(sizeof(char) * (l+2));
        strcpy(result->path, "/");
        strcat(result->path, temp_path1);
        }
    /** The following handles the situation that the path doesn't end with '/', sometimes this situation will result in status 301.
    * But adding these codes may result in status 404.
    */   
    // if(result->path[strlen(result->path)-1]!='/'){
    //     char* temp_path2 = (char*)malloc(sizeof(char) * (strlen(result->path)+1));
    //     slice_str(result->path, temp_path2, 0, strlen(result->path), 0);
    //     result->path = (char*)malloc(sizeof(char) * (strlen(temp_path2)+2));
    //     strcpy(result->path, temp_path2);
    //     strcat(result->path, "/");
    //     }
    }

    regfree(&compiled);

}

/** Check whether the two hosts are similar: except for the first component, other components of the host shold be the same, 
* also the number of components in the host should be the same.
*/
static int similarHost(char* phost, char* chost){
    char* temp_phost = (char*)malloc(sizeof(char) * (strlen(phost)+1));
    char* temp_chost = (char*)malloc(sizeof(char) * (strlen(chost)+1));

    slice_str(phost, temp_phost, 0, strlen(phost), 0);
    slice_str(chost, temp_chost, 0, strlen(chost), 0);

    char* save_point1;
    char* save_point2;

    char *token1 = strtok_r(temp_phost, ".", &save_point1);
    char *token2 = strtok_r(temp_chost, ".", &save_point2);


    while(token1!=NULL && token2!=NULL){


        token1 = strtok_r(NULL, ".", &save_point1);
        token2 = strtok_r(NULL, ".", &save_point2);

        if(token1!=NULL && token2 == NULL) return 0;
        if(token2!=NULL && token1 == NULL) return 0;
        if(token2 ==NULL && token1 == NULL) break;

        if(strcmp(token1,token2)!=0) return 0;
    }

    free(temp_phost);
    free(temp_chost);

    return 1;
}

/** Check whether the url in "href" tag is absolute or relative one.
* If the url is a relative one, we need to convert it to the absolute url.
* Then, we will check whether this absolute url is valid, duplicate or has similar host to the parent url.
*/
static char* strToFetch(char* parent, const char* href){

    struct params * purl = (struct params*)malloc(sizeof(struct params));
    struct params * curl = (struct params*)malloc(sizeof(struct params));

    getParams(parent, purl);

    if(isValid((char*)href) == 0) return NULL;
    /** If the URL in "href" tag is relative and with form "implied host + protocol + directory" and without any "/" symbol,
    * like "a.html"; then we only need to add the scheme, host and part of path of parent url to it to form the absolute url.
    */
    if(href[0]!= '/' && href[0]!= '.' && strstr((char*)href, HTTP_TAG) == NULL && strlen(href)!=0){
        char* ret = strrchr(parent, '/');
        int pos = (int)(ret - parent);
        char* b = malloc(sizeof(char) *(pos + 2)); 
        slice_str(parent, b, 0, pos+1, 0);
        char* res = malloc(sizeof(char) *(strlen(b) + strlen(href) + 1)); 
        strcpy(res, b);
        strcat(res, href);
        strcat(res, "\0");

        if(isValid(res) == 0) return NULL;
        if(strcmp(parent, res)==0) return NULL;
        //Note: res must have the same host as parent url
        return res;
    }

    getParams((char*)href,curl);

    
    // Check whether the url in "href" tag is a relative url, if it is, convert it to corresponding absolute url.
    if(strlen(curl->path) == 0){
        curl->path = (char*)malloc(sizeof(char) * 2);
        curl->path = "/\0";
    }


    if(strlen(curl->host)== 0){
        curl->host = (char*)malloc(sizeof(char) * strlen(purl->host));
        // The ending of purl-host is "\0", therefore we only need to copy from index=0 to index=strlen(purl->host)-1
        slice_str(purl->host, curl->host, 0, strlen(purl->host), 0);
    }

    if(strlen(curl->scheme)!=0 && strcmp(curl->scheme, HTTP_TAG)!=0) {
        return NULL;
    }


    char* child = malloc(sizeof(char) *(strlen(SCHEME) + strlen(curl->host) + strlen(curl->path) + 1)); 
    strcpy(child, SCHEME);
    strcat(child, curl->host);
    strcat(child, curl->path);
    strcat(child, "\0");


    if(isValid(child) == 0) return NULL;

    // Indicate two url pointing to the same page.
    if(strcmp(parent, child)==0) return NULL;

    // If the url is required to be fetched, the host of this url should be similar to the "parent" url's host, except for the first component.
    if(similarHost(purl->host, curl->host)==0) return NULL;

    free(purl);
    free(curl);

    return child;
}


// Use google gumbo to traverse all "href" tags in HTML page and extract all urls.
static void search_for_links(vec_str_t *url_vec, GumboNode* node, char*phost, char* ppath) {


  if (node->type != GUMBO_NODE_ELEMENT) {
    return;
  }
  GumboAttribute* href;
  if (node->v.element.tag == GUMBO_TAG_A && (href = gumbo_get_attribute(&node->v.element.attributes, "href"))) {
    char* parent = malloc(sizeof(char)*(strlen(SCHEME) + strlen(phost) + strlen(ppath) + 1)); 
    strcpy(parent, SCHEME);
    strcat(parent, phost);
    strcat(parent, ppath);
    strcat(parent, "\0");
    // When the converted absolute url satisfies the requirement, we store it into the vector.
    char* f = strToFetch(parent, href->value);
    if( f != NULL){
        vec_push(url_vec, f);
    }

    free(parent);

  }

  GumboVector* children = &node->v.element.children;
  for (unsigned int i = 0; i < children->length; ++i) {
    search_for_links(url_vec,(GumboNode*)(children->data[i]), phost, ppath);
  }
}

// Parse the HTTP response.
static map_str_t parseResponse(char* buffer){

    map_str_t m;
    map_init(&m);

    int pos = 0;
    int len = strlen(buffer);

    /** Located the position of the empty line in response, 
    * we should split the header and content of response based on this empty line.
    */
    if (len > 0){
        char *pfound = strstr(buffer, EMPTY_LINE); 
    if (pfound != NULL){
        pos = (int) (pfound - buffer); 
        }
    } 


    int start = pos + 4;

    char* result;
    
    if( (len-start) <= MAX_CONTENT_LEN) {
        result = (char*)malloc(sizeof(char) * (len-start+1)); 
    }else{
        result = (char*)malloc(sizeof(char) * (MAX_CONTENT_LEN+1));
    }

    slice_str(buffer, result, start, len, 0);

    int contentlen = (int)(strlen(buffer) - pos - 4);

    char* header = (char*)malloc(sizeof(char) * (pos+1));


    slice_str(buffer, header, 0, pos, 0);

    int f = 0;
    char *temp;
    // A pointer to a char * variable that is used internally by strtok_r() in order to maintain context between successive calls that parse the same string.
    char *end_str;

    char *temp_header = (char*)malloc(sizeof(char) * (strlen(header)+1));
    slice_str(header, temp_header, 0, strlen(header), 0);
    // Use this pointer to tokenize each line in the header
    char *token1 = strtok_r(temp_header, "\r\n", &end_str);

    // Parse the header information and store them into a map
    while (token1 != NULL)
    {   
        char *temp_token1 = (char*)malloc(sizeof(char) * (strlen(token1)+1));
        slice_str(token1, temp_token1, 0, strlen(token1), 0);
        if(f==0){
            // Similar function to *end_str
            char *end_token1;
            // Use this pointer to tokenize each component in each line of header, need to split by " " in first line, and by ":" in other lines
            char *token2 = strtok_r(temp_token1, " ", &end_token1);
            token2 = strtok_r(NULL, " ", &end_token1);
            map_set(&m, "status", token2);
            f++;
        }else{
            // Similar function to *end_str
            char *end_token2;
            char *token2 = strtok_r(temp_token1, ":", &end_token2);
            temp = token2;
            char* tptr = (char*)malloc(sizeof(char) * (strlen(temp)+1));
            slice_str(temp, tptr, 0, strlen(temp), 1);

            token2 = strtok_r(NULL, ":", &end_token2);
            // strip the leading whitespace in value
            char* s = (char*)malloc(sizeof(char) * strlen(token2));
            slice_str(token2, s, 1, strlen(token2), 0);
            map_set(&m, tptr, s);
        }
        token1 = strtok_r(NULL, "\r\n", &end_str);
        
    }
    // Store the response content into the map.
    map_set(&m, "response", result);

    // For key that may not exist in the map, when extracting the corresponding value, need to check whether the value is NULL and handle the casting.
    char* num = map_get(&m, "content-length")==NULL ? (char*)map_get(&m, "content-length") : *map_get(&m, "content-length");
    char* type = map_get(&m, "content-type")==NULL ? (char*)map_get(&m, "content-type") : *map_get(&m, "content-type");

    // For the page which is truncated or doesn't have "MIME-Type: text/html" in its header, we don't need to parse the page.
    char* fetchable = "1";

    if( (num != NULL && atoi(num) != contentlen) || type==NULL || strstr(type,MIME_TYPE)==NULL){
        fetchable = "0";
    }

    map_set(&m, "fetchable", fetchable);


    return m;

}


// Here we introduce the host and path of parent level of url to deal with the situation of relative sub-level url.
static void dealwithCrawling(vec_str_t *url_vec, char* content, char*phost, char* ppath){
  
    if(content ==NULL) return;
    if(content!=NULL && strlen(content)==0) return;
    GumboOutput* output = gumbo_parse(content);
    search_for_links(url_vec,output->root, phost, ppath); 
    gumbo_destroy_output(&kGumboDefaultOptions, output);

}

// Here, we use the components of target URL to construct a HTTP requiest and send it to get the HTTP response, which includes HTML page.
static void getHTML(map_int_t *urls, vec_str_t *url_vec, int sockfd, char*host, char* path, int flag, int auth_flag)
{   
    int c, n;
    char *request;

    if(auth_flag==0){
         c = asprintf(&request, format, path, host, USER_NAME, MIME_TYPE);
    }else{
         c = asprintf(&request, auth_format, path, host, USER_NAME, CREDENTIAL, MIME_TYPE);
    }


    if(c<0)
    {
        perror("ERROR formatting the request");
        exit(EXIT_FAILURE);
    }

    n = write(sockfd,request,strlen(request));
    if (n < 0) 
    {
        perror("ERROR writing to socket");
        exit(EXIT_FAILURE);
    }

    bzero(buffer,MAX_CONTENT_LEN+1);

    int received = 0;
    int bytes;

    // Use for loop to receive the HTTP response, in this way, we can receive the full response.
    while(received < MAX_CONTENT_LEN){
        bytes = recv(sockfd, buffer + received, MAX_CONTENT_LEN - received, 0);
        if(bytes<0){
            perror("recv() failed or connection closed");
            exit(EXIT_FAILURE);
        }
        if(bytes == 0) break;   
        received += bytes;
    }


    buffer[received] = '\0';
   
    free(request);

    // Parse the HTTP response.
    map_str_t info = parseResponse(buffer);

    char* t = *map_get(&info, "fetchable");
    char* status = *map_get(&info, "status");
    int code = atoi(status);

    char *whole = malloc(sizeof(char)*(strlen(SCHEME) + strlen(host) + strlen(path) + 1)); 
    strcpy(whole, SCHEME);
    strcat(whole, host);
    strcat(whole, path);
    strcat(whole, "\0");


    // If the URL is the commandline input, then we need to stop the program if its HTML page is not fetchable.
    if(flag==1 && strcmp(t,"0")==0){
        fprintf(stderr, "The corresponding HTML page is truncated or with incorrect MIME-Type\n");
        exit(EXIT_FAILURE);
    // If the URL is the not commandline input, then we don't need to stop the program if its HTML page is not fetchable.    
    }else if(flag==0 && strcmp(t,"0")==0){
        fprintf(stderr, "Truncated or with incorrect MIME-Type: %s\n", whole);
        return;
    // Deal with different status codes when the HTML page is fetchable.    
    }else if(strcmp(t,"1")==0){
        if(code == STATUS_SUCCESS){
            printf("Fetched the page successfully: %s, status code: %d\n", whole, code);
            map_set(urls, whole, code);

        }else if(code!= STATUS_SUCCESS){
            /** Here, we treat failure with code 404, 410, 414 as Permanent Failure, code 503, 504 as Temporary Failure.
            * For Permanent Failure, we just report the failure and parse the corresponding HTML pages.
            *  For Temporary Failure, we can parse the HTML page firstly, and then retry this URL later. 
            * The URLs fetched at the first time in HTML page will not be tried at the second time.
            */ 
            if(code == STATUS_PAGE_NOT_FOUND){
                printf("Page Not Found: %s, status code: %d\n", whole, code);
                map_set(urls, whole, code);
            }else if(code == STATUS_GONE){
                printf("Page Is Gone: %s, status code: %d\n", whole, code);
                map_set(urls, whole, code);
            }else if(code == STATUS_URI_TOO_LONG){
                printf("URI Is To Long: %s, status code: %d\n", whole, code);
                map_set(urls, whole, code);
            }else if(code == STATUS_SERVICE_UNAVAILABLE){
                /** If this url has suffered temporary failures before and experience temporary failure again, we don't retry it one more time.
                * Only the url that experience temporary failure at the first time needs to retry.
                */
                if(map_get(urls, whole)!=NULL){
                if(*map_get(urls, whole) == STATUS_GATEWAY_TIMEOUT || *map_get(urls, whole) == STATUS_SERVICE_UNAVAILABLE){
                    printf("Temporary failure again, No retry anymore: %s, status code: %d\n", whole, code);
                    return;
                }}
                printf("Service Unavailable, try again later: %s, status code: %d\n", whole, code);
                // We need to insert the url at the beginning of the vector, so that a period of time will pass before we retry this url again.
                vec_push(url_vec, whole);
                vec_reverse(url_vec);
                map_set(urls, whole, code);
            }else if(code == STATUS_GATEWAY_TIMEOUT){

                if(map_get(urls, whole)!=NULL){
                if(*map_get(urls, whole) == STATUS_GATEWAY_TIMEOUT || *map_get(urls, whole) == STATUS_SERVICE_UNAVAILABLE){
                    printf("Temporary failure again, No retry anymore: %s, status code: %d\n", whole, code);
                    return;
                }}
                printf("Gateway Timeout, try again later: %s, status code: %d\n", whole, code);
                vec_push(url_vec, whole);
                vec_reverse(url_vec);
                map_set(urls, whole, code);
            }else if(code == STATUS_MOVE_PERMANENTLY){
                char* location = *map_get(&info, "location");
                if(location!=NULL && strlen(location)!=0){
                    printf("The resource is moved permanently: %s, status code: %d\n", whole, code);
                    printf(".............Redirecting to: %s\n", location);
                    vec_push(url_vec, location);
                    map_set(urls, whole, code);
                }else{
                    printf("The resource is moved permanently without indicating a new URI: %s, status code: %d\n", whole, code);
                }
            }else if(code == STATUS_UNAUTHORIZED){
                printf("Unauthorized, attempting to retry with authentication header: %s, status code: %d\n", whole, code);
                retry = malloc(sizeof(char)*(strlen(whole)+ 1)); 
                slice_str(whole, retry, 0, strlen(whole), 0);
                vec_push(url_vec, whole);
                map_set(urls, whole, code);           
            }
            else{
                printf("Something wrong with the page... %s, status code: %d\n", whole, code);
                map_set(urls, whole, code);
                return;
            }
        }


        numOfURL++;
        if(numOfURL == MAX_PAGE_NUM){
            printf("In total %d pages are crawled, exit safely...\n", MAX_PAGE_NUM);
            exit(EXIT_SUCCESS);
        }
    }


    char* content = map_get(&info, "response")==NULL ? (char*)map_get(&info, "response") : *map_get(&info, "response");

    // Crawl and deal with all urls in the HTML page content.
    dealwithCrawling(url_vec,content, host, path);

    map_deinit(&info);


}

static void createNewSocket(map_int_t *urls, vec_str_t *url_vec, char* url, int flag, int auth_flag){

    // Since we need to retry the url with temporary failures, therefore, we need to create sockets again for these urls.
    // For other urls that we have fetched, we don't need to try it one more time. --- No duplicate fetch!
    if(map_get(urls, url) && *map_get(urls, url)!= STATUS_SERVICE_UNAVAILABLE && *map_get(urls, url)!= STATUS_GATEWAY_TIMEOUT && *map_get(urls, url)!= STATUS_UNAUTHORIZED){ 
        return;
    }
    else{
        int sockfd;
        struct sockaddr_in serv_addr;
        struct hostent * server;
        struct params * p = (struct params*)malloc(sizeof(struct params));

        // Decouple the components of the url.
        getParams(url, p);


        // If the URL is the commandline input, then we need to stop the program if its scheme is not HTTP.
        if(flag==1 && strcmp(p->scheme,HTTP_TAG) != 0){
            fprintf(stderr, "The scheme of url is not http\n");
            exit(EXIT_FAILURE);
        }else if(flag==0 && strcmp(p->scheme,HTTP_TAG) != 0){
            return;
        }

        /* Translate host name into peer's IP address ;
        * This is name translation service by the operating system. */
        server = gethostbyname(p->host);

        // Check whether the server is valid.
        if (server == NULL)
        {
            if(flag==1){
                fprintf(stderr, "ERROR, No Such Host: %s\n", p->host);
                exit(EXIT_FAILURE);
            }else{
                return;
            }

        }


        /* Building data structures for socket */
        bzero((char *)&serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        bcopy(server->h_addr_list[0], (char *)&serv_addr.sin_addr.s_addr, server->h_length);
        int portn = atoi(p->port);
        serv_addr.sin_port = htons(portn);

        /* Create TCP socket -- active open*/
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0)
        {
            perror("ERROR opening socket");
            exit(EXIT_FAILURE);
        }

        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            perror("ERROR connecting");
            exit(EXIT_FAILURE);
        }

        // Construct a HTTP request and get the HTML content from the HTTP response.
        getHTML(urls, url_vec, sockfd, p->host, p->path, flag, auth_flag);

        close(sockfd);

        free(p);

    }

}


int main(int argc, char ** argv)
{

    /* Check the correctness of command line inputs*/
    if (argc < 2)
    {
        fprintf(stderr, "Usage %s TargetURL\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Check whether the input url is valid.
    if(isValid(argv[1])){

    }else{
        fprintf(stderr, "Invalid or Long URL %s, type in URL without (..#?) or URL encoded character and with length less than 1000 bytes\n", argv[1]);
        exit(EXIT_FAILURE);

    }

    // Define the data structure to store urls that need to fetch.
    map_int_t urls;
    vec_str_t url_vec;

    map_init(&urls);
    vec_init(&url_vec);
    createNewSocket(&urls, &url_vec, argv[1],1,0);

    // Pop one url at a time.
    while(url_vec.length>0){
        char* url = vec_pop(&url_vec);
        if( retry!=NULL && strcmp(url, retry)==0){
            createNewSocket(&urls, &url_vec, url, 0,1);
        }else{
        createNewSocket(&urls, &url_vec, url, 0,0); }
    }


    map_deinit(&urls);
    vec_deinit(&url_vec);

    return 0;
}
