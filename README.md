TinyIRRDBCache
==============

Manages a local cache of various Internet Routing Registry Databases (IRRDs) for quick lookups.

The API is rudimentary, the main value of this code is in the efficient caching.

original code (c) by Michael Friese (mfr at ecix net)
restructured by Thorben Krüger (tkr at ecix net)

(c) 2015 Peering GmbH (ECIX)

    
Notes/Known Issues
------------------
    
 - Not for production use, just serves as an Example(TM)
 - **The binary file on disk can get corrupted if the process is killed at the wrong time or network connection is lost**
 - Only tested with nodejs v0.10.36
 - Lots of stuff is hard coded
   - database addresses
   - http server port (near end of file)
   - tmp file path/names/suffixes (search code for '/tmp' and '.tiny')
 - The server does not expose all potential functionality
 - Different API calls return differently formatted results (see below)

Usage
-----

 - Download the file and run "node *filename*"
 - Wait for databases to be cached (signified by "Exported *dbname*")
 - When rerunning and cache files are found, wait for "Import done; *dbname*"

try
 - curl localhost:8086/ripe/AS-CHAOS/v6
   - gets all v6 prefixes for that macro from the ripe DB
 - curl localhost:8086/radb/15169/v4 | less
   - gets all v4 prefixes for AS15169 (Google). Note the formatting
 - curl localhost:8086/radb/15169/v6 | less
   - gets all v6 prefixes for AS15169, encoded in the same way as the v4 addresses (sorry)
 - curl localhost:8086/dump | less
   - gets a JSON dump of everything that has been cached


Hacking
-------
    
 - convenience functions to convert between different IP representations are found near the beginning of this file
 - consistent API call results (e.g., IP formatting) would be sensible
 - database details and file paths as well as server listen address should go into a config JSON
 - temporary files should be used when writing caches, atomic (fs-level) rename once successful
 - forks welcome (via github, or email patches to tkr at ecix net)
