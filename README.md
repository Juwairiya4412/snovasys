\# TrustVault — Secure Document Management System



\## Overview



TrustVault is a web-based document management prototype that allows registered users to upload, access, share, and manage documents with role-based permissions.



\## Features



\- User login and session management

\- Role-based access for administrators and document owners

\- Document upload and listing

\- Secure document downloads with permission checks

\- Document sharing with read or edit permissions

\- Revocation of shared access

\- Document deletion

\- Admin Activity Logs for recording and reviewing document-related events



\## Technology



\- Node.js

\- Express.js

\- SQLite database using `better-sqlite3`

\- HTML, CSS, and JavaScript



\## Run Locally



1\. Install Node.js.

2\. Open a terminal in the project directory.

3\. Install dependencies:



&#x20;  ```powershell

&#x20;  npm install

&#x20;  ```



4\. Start the application:



&#x20;  ```powershell

&#x20;  node .\\server.js

&#x20;  ```



5\. Open `http://localhost:3000/` in your browser.



Keep the terminal running while using the application.



\## Testing



The prototype has been exercised locally for document uploads, downloads, sharing, revocation, Activity Logs, and document deletion. Test the application's current behavior in your own environment before relying on it.



\## Security Notice



This is a development prototype. Before production deployment, review authentication and session settings, configure HTTPS and secure cookies, validate uploaded file contents, and test authorization for every document operation.



\## Repository



GitHub: https://github.com/Juwairiya4412/snovasys



