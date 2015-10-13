#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sysexits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <signal.h>
//#include <ctype>
#include <glib.h>

#include "request.h"
#include "mimetypes.h"

#define BUFFER_SIZE 4096

// making these global will be useful for Assignment 7.
static char input_buffer[BUFFER_SIZE];
static size_t input_buf_pos = 0;
static volatile bool keep_running = true;
static const char *document_root;

//lookup address
ssize_t lookup_address(char *host, char *port, struct sockaddr **addr)
{
    struct addrinfo hints = {
        AI_V4MAPPED,
        AF_INET6,
        SOCK_DGRAM,
        0
    };
    struct addrinfo *ai;
    ssize_t len;
    int code;
    code = getaddrinfo(host, port, &hints, &ai);
    if (code < 0) {
        return -1;
    }

    // now we copy the socket address
    len = ai->ai_addrlen;
    *addr = malloc(len);
    memcpy(*addr, ai->ai_addr, len);
    freeaddrinfo(ai);
    return len;
}

/**
 * Read a request from the input stream.
 */
static req_t* read_request(int fd)
{
    req_t *req = req_create();
    ssize_t nbytes, nused;
    while (!req_is_complete(req)) {
        nbytes = read(fd, input_buffer, BUFFER_SIZE);
        if (nbytes < 0) {
            if (errno == EINTR) {
                // interrupted, try again
                continue;
            } else {
                goto abort;
            }
        } else if (nbytes == 0) {
            // no data - end of file, but request is incomplete
            return NULL;
        }
        // we have data!
        nused = req_parse(req, input_buffer, nbytes);
    }

    /* if we are here, then two things are true:
     * - the request is complete
     * - nused has the number of bytes of input_buffer that have been used
     */
    input_buf_pos = nused;
    return req;

abort:
    req_destroy(req);
    return NULL;
}

/**
 * Send an error message.  This takes variable arguments, like printf, and
 * puts them together to make the error message.
 */
static void send_error(FILE *stream, int code, const char *reason, const char *fmt, ...)
{
    va_list ap;
    char *details;

    va_start(ap, fmt);
    details = g_strdup_vprintf(fmt, ap);
    va_end(ap);

    fprintf(stream, "HTTP/1.0 %d %s\r\n", code, reason);
    fprintf(stream, "Content-Type: text/plain\r\n");
    fprintf(stream, "Content-Length: %zd\r\n", strlen(details) + 2);
    fprintf(stream, "\r\n%s\r\n", details);
    exit(0);
}

/**
 * Send a file to the client.
 *
 * @param req The request.
 * @param filepath The path to the file (in UNIX space).
 * @param sb The result of calling 'stat' on the file.
 */
static int send_file(FILE *stream, req_t *req, const char *filepath, struct stat *sb)
{
    // regular file, send it
    char *buf = g_malloc(BUFFER_SIZE);
    ssize_t nb;
    int result = 0;
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        switch (errno) {
            case ENOENT:
                send_error(stream, 404, "Not Found",
                           "The resource %s could not be found.",
                           req_path(req));
                break;
            case EACCES:
                send_error(stream, 401, "Forbidden",
                           "The resource %s could not be read.",
                           req_path(req));
                break;
            default:
                send_error(stream, 500, "Internal Server Error",
                           "%s: %s", req_path(req), strerror(errno));
                break;
        }
        // the error should have been picked up earlier (calling 'stat'), so
        // return with error
        return -1;
    }

    fprintf(stream, "HTTP/1.0 200 OK\r\n");
    const char *ctype = guess_content_type(filepath);
    if (ctype != NULL) {
        fprintf(stream, "Content-Type: %s\r\n", ctype);
    }
    size_t length = sb->st_size;
    struct tm *mod_time = gmtime(&(sb->st_mtime));
    fprintf(stream, "Content-Length: %zd\r\n", length);
    char TIME_BUF[512];
    strftime(TIME_BUF, 512, "%a, %d %b %Y %H:%M:%S %Z", mod_time);
    fprintf(stream, "Last-Modified: %s\r\n", TIME_BUF);
    fprintf(stream, "\r\n");
    size_t total_bytes = 0;
    while ((nb = fread(buf, 1, BUFFER_SIZE, file)) > 0) {
        if (total_bytes + nb > length) {
            fprintf(stderr, "%s: file size changed\n", filepath);
            nb = length - total_bytes;
            result = -1;
            break;
        }
        size_t written = 0;
        while (written < nb) {
            size_t wr = fwrite(buf + written, 1, nb - written, stream);
            if (wr > 0) {
                written += wr;
            } else {
                // fwrite returns 0 for error
                // too late to send an error to the client to 
                perror("output");
                result = -1;
                break;
            }
        }
        total_bytes += nb;
    }
    if (!feof(file)) {
        perror(filepath);
        result = -1;
    }

    fclose(file);
    // TODO send stat data

    return result;
}

/**
 * Send a directory listing (index).
 */
static int send_dir_index(FILE *stream, req_t *req, const char *path)
{
    char timebuf[512];
    DIR *dir = opendir(path);
    struct dirent *de;
    if (!dir) {
        send_error(stream, 500, "Internal server error", "Failed to open directory\n");
        return -1;
    }

    fprintf(stream, "HTTP/1.0 200 OK\r\n");
    fprintf(stream, "Content-Type: text/html\r\n");
    fprintf(stream, "\r\n");
    fprintf(stream, "<!doctype html>\n");
    fprintf(stream, "<html><head>\n");
    fprintf(stream, "<title>%s</title>\n", req_path(req));
    fprintf(stream, "</head><body>\n");
    fprintf(stream, "<h1>Index of %s</h1>\n", req_path(req));
    fprintf(stream, "<ul>\n");

    de = readdir(dir);
    while (de) {
        fprintf(stream, "<li><a href=\"%s\">%s</a> (",
                de->d_name, de->d_name);
        char *fpath = g_build_filename(path, de->d_name, NULL);
        struct stat sb;
        if (stat(fpath, &sb) < 0) {
            fprintf(stream, "inaccessible");
        } else {
            if (S_ISDIR(sb.st_mode)) {
                fprintf(stream, "directory");
            } else if (S_ISREG(sb.st_mode)) {
                fprintf(stream, "%zd bytes", sb.st_size);
            } else {
                // just use 'special' as a catch-all
                fprintf(stream, "special");
            }
            strftime(timebuf, 512, "%b %e, %Y %H:%M %Z",
                     localtime(&(sb.st_mtime)));
            fprintf(stream, ", last modified on %s", timebuf);
        }
        fprintf(stream, ")\n");
        de = readdir(dir);
    }

    fprintf(stream, "</ul>\n");
    fprintf(stream, "</body>\n");

    closedir(dir);

    return 0;
}

/**
 * Handle an HTTP request and produce an appropriate response.
 *
 * @param req The parsed HTTP request.
 * @param stream The stream to which the response should be printed.
 */
static int handle_request(req_t *req, FILE *stream)
{
    g_return_val_if_fail(req != NULL, -1);
    g_return_val_if_fail(req_is_complete(req), -1);
    g_return_val_if_fail(req_is_valid(req), -1);
    g_return_val_if_fail(document_root != NULL, -1);

    const char *path = req_path(req);

    // check path validity
    if (strstr(path, "..")) {
        // oops, contains '..'
        send_error(stream, 400, "Bad Request", "Request path is invalid");
        return 0;
    } else if (*path != '/') {
        // oops, is not absolute (no leading '/')
        send_error(stream, 400, "Bad Request", "Request path is invalid");
        return 0;
    }

    int result = 0;
    // combine path with document root to get a UNIX file path
    char *filepath = g_build_filename(document_root, path, NULL);
    // now start examining it
    struct stat sb;
    if (stat(filepath, &sb) < 0) {
        // there is an error with the file
        switch (errno) {
            case ENOENT:
                send_error(stream, 404, "Not Found",
                           "The resource %s could not be found.", path);
                break;
            case EACCES:
                send_error(stream, 401, "Forbidden",
                           "The resource %s could not be read.", path);
                break;
            default:
                send_error(stream, 500, "Internal Server Error",
                           "%s: %s", path, strerror(errno));
                result = -1;
                break;
        }
    } else if (S_ISDIR(sb.st_mode)) {
        if (filepath[strlen(filepath) - 1] == '/') {
            // we have a directory with a proper path. check for index.html.
            char *ind_fp = g_build_filename(filepath, "index.html", NULL);
            if (stat(ind_fp, &sb) < 0) {
                // not found
                result = send_dir_index(stream, req, filepath);
            } else {
                // index.html exists
                result = send_file(stream, req, ind_fp, &sb);
            }
            g_free(ind_fp);
        } else {
            // no trailing '/', send a redirect
            fprintf(stream, "HTTP/1.0 301 Moved Permanently\r\n");
            const char *host = req_host(req);
            if (host) {
                fprintf(stream, "Location: http://%s%s/\r\n", req_host(req), path);
            } else {
                // not entirely conformant, but the best we can do
                fprintf(stderr, "warning: no host in request\n");
                fprintf(stream, "Location: %s/\r\n", path);
            }
            fprintf(stream, "\r\n");
        }
    } else if (S_ISREG(sb.st_mode)) {
        result = send_file(stream, req, filepath, &sb);
    } else {
        send_error(stream, 401, "Forbidden", "Access denied.");
    }

    g_free(filepath);

    return result;
}

//signal... stuff

void handle_sigchld(int sig)
{
    int status;
    pid_t pid;

    while ((pid = wait(&status)) > 0) {
        fprintf(stderr, "child %d exited with status %d\n", pid, status);
    }       
}

void handle_shutdown(int sig)
{
    keep_running = false;
} 

void setup_signals(void)
{
    struct sigaction action;

    sigemptyset(&(action.sa_mask));
    action.sa_handler = handle_sigchld;
    action.sa_flags = SA_NOCLDSTOP;

    if (sigaction(SIGCHLD, &action, NULL)) {
        perror("sigaction");
        exit(EX_OSERR);
    }

    action.sa_handler = handle_shutdown;
    action.sa_flags = 0;

    if (sigaction(SIGINT, &action, NULL)) {
        perror("sigaction");
        exit(EX_OSERR);
    }
    if (sigaction(SIGTERM, &action, NULL)) {
        perror("sigaction");
        exit(EX_OSERR);
    }
}


/**
 * The main function that handles an HTTP request.
 */
int main(int argc, char **argv)
{
	//obtain arguments
	int code;
	char *host = "::";
	char *port = "4080";
	char act_host[NI_MAXHOST];
	char act_port[NI_MAXSERV];
	//ssize_t result;
	//size_t bytes_done, req_len;
	struct sockaddr *addr;
	ssize_t addr_len;
	char **prog_args;
	FILE *handler;
	setup_signals();

	while((code = getopt(argc, argv, "h:p:"))>0) {
		switch(code){
			case 'h':
				host = optarg;
				break;
			case 'p':
				port = optarg;
				break;
			case '?':
			default:
				fprintf(stderr, "bad argument\n");
				exit(EX_USAGE);
		}
	}
	prog_args = malloc((argc - optind + 1) * sizeof(char*));
	for (int i = 0; i < argc - optind; i++) {
		prog_args[i] = argv[optind + i];
	}
	prog_args[argc-optind] = NULL;

	addr_len = lookup_address(host, port, &addr);
	if (addr_len < 0) {
		fprintf(stderr, "%s:%s: %s\n", host, port, gai_strerror(addr_len));
		exit(EXIT_FAILURE);
	}

	getnameinfo(addr, addr_len, act_host, NI_MAXHOST, act_port, NI_MAXSERV,
		NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "listening on %s:%s\n", act_host, act_port);

	int sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	code = bind(sock, addr, addr_len);
	if (code < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	code = listen(sock, 5);
	if (code < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	pid_t group = setpgrp();
//	fprintf(stderr, "process group %d\n", group);

//wait for connection and then process the request.
	while(keep_running){
		fprintf(stderr, "waiting for connection \n");
		struct sockaddr_in6 c_addr;
		socklen_t c_addr_len = sizeof(struct sockaddr_in6);
		int client = accept(sock, (void*) &c_addr, &c_addr_len);
		if(client < 0){
			if(errno == EINTR){
				continue;
			}else{
				perror("accept");
				exit(EXIT_FAILURE);
			}
		}
		pid_t child = fork();
		if(child < 0){
			perror("fork");
			exit(EX_OSERR);
		}else if(child){
			close(client);
		}else{
			//close(sock);
			req_t *req;
			document_root = argv[optind];

			req = read_request(client);
			handler = fdopen(client, "r+");
	
			if (!req && errno != 0) {
			// internal error
				perror("httpd");
				send_error(handler, 500, "Internal Server Error",
					   "Internal server error: %s", strerror(errno));
				return 1;
			} else if (!req || !req_is_valid(req)) {
				send_error(handler, 400, "Bad Request", "Incomplete or invalid request.");
				return 0;
			} else {
				//handler = fdopen(client, "r+");
				if (handle_request(req, handler) < 0) {
				    return 1;
				} else {
				    fclose(handler);
				    close(client);
				    free(addr);
				    return 0;
				}
			}
			close(sock);
			close(client);
			fclose(handler);
		}
	}
	close(sock);
	free(addr);
	return 0;
}
