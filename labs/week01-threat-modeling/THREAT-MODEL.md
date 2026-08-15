# Threat Model — <app name>

## 1. Data-flow diagram
(![alt text](diagram-export-8-15-2026-4_13_06-PM.png))

## 2. Elements & trust boundaries
| Element | Type (process/store/entity/flow) | Trust boundary crossed? |
|---|---|---|
| Web client | external entity | yes (Internet → app) |
| Flask app | process |yes (Internet ↔ app and app ↔ data tier)|
| SQLite DB (`notes.db`) | data store |yes (app → data tier)|
| `uploads/` store | data store |yes (app → data tier)|

## 3. STRIDE analysis
| Element | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| /notes |Yes (accepts owner input without auth)| |Yes (no logging)| | | |
| /upload | |Yes (arbitrary-file-write pass f.filename)|Yes (no logging)|Yes (reveals the path in the response)| | |
| /files/<name> | | |Yes (no logging)|Yes (path-traversal vulnerability with ../)| | |

## 4. Top 5 risks (likelihood × impact) + mitigation
1. Arbitrary File Write (Tampering at /upload) 
    Risk: Attackers can upload files with malicious names (e.g., overwrite system files, database files like notes.db, or embed a webshell) because the system logs files using the name f.filename directly submitted by the user. 
    Mitigation: Use functions like secure_filename() to filter filenames, or switch to using random filenames (e.g., UUIDs) for logging to the server, and limit the types of files allowed to be uploaded (Allow-list).
2. Path Traversal (Information Disclosure at /files/<name>) 
    Risk: An attacker can insert ../ into the filename to bypass the uploads/ folder and access other sensitive files on the server. 
    Mitigation: Check and prevent the inclusion of ../ characters in parameters, or use secure_filename() in conjunction with ensuring that the final path to be accessed remains strictly within the uploads/ folder.
3. Unnauthenticated Note Creation / Spoofing (Spoofing at /notes) 
    Risk: Anyone can send a request and impersonate the owner (e.g., "alice") without authentication, leading to loss of data trustworthiness. 
    Mitigation: Add an authentication system such as Session or JWT and retrieve post owner information only from verified data, instead of trusting values ​​sent from the client.
4. Server Path Leakage (Information Disclosure at /upload) 
    Risk: The system immediately reflects the resolved save path back in the response after the upload is complete, allowing attackers to know the server's internal folder structure. 
    Mitigation (Solution): Return only the upload confirmation message or only the filename/ID instead of the full server path.
5. Complete Lack of Logging (Repudiation on All Endpoints) 
    Risk: The application does not log any transaction history. If an attack or data leak occurs, it will be impossible to trace back who did it, when it happened, and what method was used. 
    Mitigation (Solution): Install a logging system for the application to record basic information such as IP address, timestamp, accessed endpoint, and HTTP status code for every request.
