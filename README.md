# AuthX — Authentication Vulnerability Assessment

AuthX is a Node.js/Express application developed for the Software Application Security course at the University of Bucharest. The project demonstrates common authentication vulnerabilities and their corresponding security mitigations.

## Project Overview

The project is organized into two branches:

* `v1-vulnerable` — intentionally vulnerable implementation used to demonstrate common authentication and session security issues.
* `v2-secure` — secured implementation containing the corresponding mitigations.

## Security Vulnerabilities

The project analyzes and mitigates the following vulnerabilities:

* Weak password policy
* Plaintext password storage
* Brute-force attacks without rate limiting
* User enumeration
* Insecure session management
* Predictable and reusable password reset tokens
* Exposed server stack traces

## Security Measures

The secure implementation includes:

* Password hashing with `bcryptjs`
* Rate limiting for authentication endpoints
* Improved session security
* Cryptographically secure password reset tokens
* Protection against user enumeration
* Safer error handling
* Audit logging

## Technologies

* Node.js
* Express.js
* SQLite
* bcryptjs
* express-session
* express-rate-limit

## Installation

Clone the repository and install the dependencies:

```bash
npm install
```

Start the application:

```bash
node app.js
```

The application runs locally at:

`http://localhost:3000`

## Project Structure

```text
PROIECT_DASS/
├── routes/
├── app.js
├── database.js
├── brute.ps1
├── brute.sh
├── package.json
├── package-lock.json
└── README.md
```

## Academic Context

Developed as part of the Software Application Security course at the Faculty of Mathematics and Computer Science, University of Bucharest.
