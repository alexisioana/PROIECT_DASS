# AuthX — Break the Login

**Student:** Pavlov Alexis-Ioana
**Curs:** Dezvoltarea Aplicatiilor Software Securizate
**Universitatea din Bucuresti**

## Branch-uri

- v1-vulnerable: cod initial vulnerabil (parole in clar, fara rate limit, user enumeration, token timestamp)
- v2-secure: cod securizat (bcrypt, rate limit, session hardening, token criptografic)

## Instalare

npm install
node app.js

Aplicatia porneste pe http://localhost:3000

## Vulnerabilitati remediate

- 4.1 Parole slabe acceptate - REMEDIAT
- 4.2 Parole stocate in clar - REMEDIAT
- 4.3 Brute force fara rate limiting - REMEDIAT
- 4.4 User enumeration - REMEDIAT
- 4.5 Sesiuni nesigure - REMEDIAT
- 4.6 Token reset predictibil si reutilizabil - REMEDIAT
- 4.7 Stack trace expus - REMEDIAT

## Tehnologii

Node.js, Express.js, SQLite, bcryptjs, express-session, express-rate-limit
