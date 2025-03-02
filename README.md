# Lunabot - IRC bot for Github webhooks

Lunabot is a simple IRC bot written in the C programming language, designed to relay GitHub webhook notifications to an IRC channel. While primarily developed for the Lunar Linux project, it can be adapted for other projects by modifying a few global constants and variables.

## Features

 - Connects to an IRC server over TLS.
 - Sends messages in the channel for:
   - New PR.
   - Pending CI build (optional).
   - CI build statuses, Failed or Success.
   - Closed PR.
   - Merged PR.
   - Label operations on PRs (optional).
 - Listens for GitHub webhook events via an embedded HTTP server.
 - Parses and formats repository events before sending them to the IRC channel.
 - Uses OpenSSL for payload signature verifications.

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
You will need to put the bot's NickServ password in .passwd and the webhook secret in .secret.  
Alternatively you can set the credentials using environment variables instead of files:
 - LUNABOT_NICKSERV_PASSWORD
 - LUNABOT_WEBHOOK_SECRET
To run the program, type './lunabot'  
Once you have an identification confirmation from the server, you need to type 'join #channel_name_here'.  

## Author
Stephane Fontaine (esselfe) 2025
