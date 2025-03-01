# Lunabot - IRC bot for Github webhooks

Lunabot is a simple IRC bot written in the C programming language, designed to relay GitHub webhook notifications to an IRC channel. While primarily developed for the Lunar Linux project, it can be adapted for other projects by modifying a few global constants and variables.

## Features

 - Connects to an IRC server over TLS.
 - Sends messages in the channel for:
   - New PR
   - Pending CI build (optional)
   - CI build statuses, Failed or Success
   - Closed PR
   - Merged PR
 - Listens for GitHub webhook events via an embedded HTTP server.
 - Parses and formats repository events before sending them to the IRC channel.
 - Uses OpenSSL for secure connections.

## Requirements

To compile and run lunabot, you will need the following dependencies installed:

 - make (The build system used).
 - gcc (The GNU C compiler).
 - libmicrohttpd (for the webhook server).
 - jansson (for the webhook JSON data parsing).
 - openssl (for secure IRC connections).
 - pthread (for multithreading support).

## Build and run
To compile the source code into an executable, type 'make' in the source directory from a terminal.
To run the program, type './lunabot'

## Author
Stephane Fontaine (esselfe) 2025
