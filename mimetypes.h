#ifndef HTTPD_MIME_TYPES_H
#define HTTPD_MIME_TYPES_H

/**
 * Guess the Content-Type of a file from its name.
 * @param file The file name.
 * @return The content type of the file, or NULL if no content type can be guessed.
 *         The returned string is owned by the content type system and must not be
 *         freed.
 */
const char* guess_content_type(const char *file);

#endif // !defined(HTTPD_MIME_TYPES_H)
