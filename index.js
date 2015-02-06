/*
TinyIRRDBCache

Manages a local cache of various Internet Routing Registry Databases (IRRDs) for quick lookups.

The API is rudimentary, the main value of this code is in the efficient caching.

original code (c) by Michael Friese (mfr at ecix net)
restructured by Thorben Krüger (tkr at ecix net)

(c) 2015 Peering GmbH (ECIX)


NOTE:
 - Not for production use, just serves as an Example(TM)
 - THE BINARY FILE ON DISK CAN GET CORRUPTED IF THE PROCESS IS KILLED AT THE WRONG TIME OR NETWORK CONNECTION IS LOST
 - Only tested with nodejs v0.10.36
 - Lots of stuff is hard coded
   - database addresses
   - http server port (near end of file)
   - tmp file path/names/suffixes (search code for '/tmp' and '.tiny')
 - The server does not expose all potential functionality
 - Different API calls return differently formatted results (see below)

USAGE:

 - Download the file and run "nodejs <filename>"
 - Wait for databases to be cached (signified by "Exported <dbname>")
 - When rerunning and cache files are found, wait for "Import done; <dbname>"

try
 - curl localhost:8086/ripe/AS-CHAOS/v6
   - gets all v6 prefixes for that macro from the ripe DB
 - curl localhost:8086/radb/15169/v4 | less
   - gets all v4 prefixes for AS15169 (Google). Note the formatting
 - curl localhost:8086/radb/15169/v6 | less
   - gets all v6 prefixes for AS15169, encoded in the same way as the v4 addresses (sorry)
 - curl localhost:8086/dump | less
   - gets a JSON dump of everything that has been cached


HACKING:
 - convenience functions to convert between different IP representations are found near the beginning of this file
 - consistent API call results (e.g., IP formatting) would be sensible
 - database details and file paths as well as server listen address should go into a config JSON
 - temporary files should be used when writing caches, atomic (fs-level) rename once successful
 - forks welcome (via github, or email patches to tkr at ecix net)
*/

var
    fs = require('fs'),
    zlib = require('zlib'),
    http = require('http'),
    spawn = require('child_process').spawn,
    net = require('net'),
    crypto = require('crypto');

process.title = 'TinyIRRDBCache';

var databases = {};

var config = {
    databases: {
        'altdb': {
            'serial': 'ftp://ftp.radb.net/radb/dbase/ALTDB.CURRENTSERIAL',
            'dump': 'ftp://ftp.radb.net/radb/dbase/altdb.db.gz',
            'realtimeHost': 'whois.altdb.net',
            //'realtimePort': 43,
            'intName': 'ALTDB'
        },
        'apnic': {
            'serial': 'ftp://ftp.radb.net/radb/dbase/APNIC.CURRENTSERIAL',
            'dump': 'ftp://ftp.radb.net/radb/dbase/apnic.db.gz',
            'realtimeHost': 'whois.radb.net',
            // 'realtimePort': 43,
            'intName': 'APNIC'
        },
        'level3': {
            'serial': 'ftp://ftp.radb.net/radb/dbase/LEVEL3.CURRENTSERIAL',
            'dump': 'ftp://ftp.radb.net/radb/dbase/level3.db.gz'
        },
        'radb': {
            'serial': 'ftp://ftp.radb.net/radb/dbase/RADB.CURRENTSERIAL',
            'dump': 'ftp://ftp.radb.net/radb/dbase/radb.db.gz',
            'realtimeType': 'whois',
            'realtimeHost': 'whois.radb.net',
            'realtimePort': 43,
            'intName': 'RADB'
        },
        'arin': {
            'serial': 'ftp://ftp.arin.net/pub/rr/ARIN.CURRENTSERIAL',
            'dump': 'ftp://ftp.arin.net/pub/rr/arin.db',
            'realtimeType': 'whois',
            'realtimeHost': 'rr.arin.net',
            //'realtimePort': 4444,
            'intName': 'ARIN'
        },
        'ripe': {
            'serial': 'ftp://ftp.ripe.net/ripe/dbase/RIPE.CURRENTSERIAL',
            'dump': 'ftp://ftp.ripe.net/ripe/dbase/ripe.db.gz',
            'intName': 'RIPE',
            'realtimeHost': 'nrtm.db.ripe.net',
            'realtimePort': 4444
        }
    }
};


var v42str = function(addr) {
    return addr[0] + '.' + addr[1] + '.' + addr[2] + '.' + addr[3] + '/' + addr[4];
};

var v62str = function(addr) {
    var shortened = false;
    var res = '';
    var tmp = '';
    for (var i = 0; i < addr[16] / 8; i += 2) {
        tmp = addr.slice(i, i + 2).toString('hex');
        res += tmp;
        res += ':';
    }
    if (!shortened) res = res + ':';
    return res + '/' + addr[16];
};

var str2v6 = function(addrIn) {
//  console.log('v6: ' + addrIn);
    var parts = addrIn.split('/');
    var addr = new Buffer(17);
    addr.fill(0);
    addr[16] = parseInt(parts[1], 10);
    var q = parts[0].split(':');
    var front = true;
    for (var i = 0; i < q.length; i++) {
        if (q[i] === '') {
            front = false;
            continue;
        }
        if (front) {
            addr.writeUInt16BE(parseInt(q[i], 16), i * 2);
        } else {
            addr.writeUInt16BE(parseInt(q[i], 16), 16 - (q.length - i) * 2);
        }
    }
    return addr;
};



var str2ip = function(addrIn) {
    var ip = addrIn.split('/');
    if (ip[0].match(/:/)) return str2v6(addrIn);
    var ipv4 = ip[0].split('.');
    var ipS = new Buffer(5);
    ipS[0] = parseInt(ipv4[0], 10);
    ipS[1] = parseInt(ipv4[1], 10);
    ipS[2] = parseInt(ipv4[2], 10);
    ipS[3] = parseInt(ipv4[3], 10);
    ipS[4] = parseInt(ip[1], 10);
    return ipS;
};


var
    masks = [0, 128, 192, 224, 240, 248, 252, 254, 255];

var repairV4 = function(addr) {
    var prefix = addr[4];
    if (prefix < 8) {
        addr[0] = addr[0] & masks[8 - (8 - prefix)];
        addr[1] = 0;
        addr[2] = 0;
        addr[3] = 0;
        return;
    }
    if (prefix < 16) {
        addr[1] = addr[1] & masks[8 - (16 - prefix)];
        addr[2] = 0;
        addr[3] = 0;
        return;
    }
    if (prefix < 24) {
        addr[2] = addr[2] & masks[8 - (24 - prefix)];
        addr[3] = 0;
        return;
            }
    if (prefix < 32) {
        addr[3] = addr[3] & masks[8 - (32 - prefix)];
    }
};

var repairV6 = function(addr) {
    var prefix = addr[16];
    if (prefix >= 128 || prefix < 0) return;
    var c = 0;
    var tmp = 0;
    var changed = false;
    while (true) {
        if (prefix < (c + 1) * 8) {
            tmp = addr[c];
            addr[c] = addr[c] & masks[8 - ((c + 1) * 8 - prefix)];
            if (c < 15) addr.fill(0, c + 1, 15);
            if (tmp != addr[c]) {
                console.log('corrected');
            }
            return;
        }
        c++;
        if (c >= 16) return;
    }
};


var TinyIRRDBCache = function(config, dbs) {
    this.config = config;
    databases = dbs;
    return this;
};

TinyIRRDBCache.prototype.init = function() {
    // Try to import databases...
    for (var dbName in this.config.databases) {
        this.initDb(dbName);
    }
};

TinyIRRDBCache.prototype.initDb = function(dbName) {
    var self = this;
    this.importDB(dbName, function(err) {
        if (!err) {
            setInterval(function() {
                self.enableRT(dbName);
            }, 60 * 1000 * 10); // Fetch all 10 minutes
            self.enableRT(dbName);
            return;
        }
        self.getDump(dbName);
    });
};

TinyIRRDBCache.prototype.enableRT = function(dbName) {
    var self = this;
    var curDB = this.config.databases[dbName];
    if (!curDB.realtimePort || !curDB.realtimeHost) {
        return;
    }
    var client = net.createConnection(curDB.realtimePort, curDB.realtimeHost, function() {
        var state = 0;
        var action = '';
        var packet = [];
        var entriesAdded = 0;
        var entriesDeleted = 0;
        var m;
        var startSerial = parseInt(databases[dbName].serial, 10);
        var latestSerial = startSerial;
        var write = function(line) {
            client.write(line + '\n');
            // console.log('> ' + line);
        };
        var process = function(line) {
            // console.log('< ' + line);
            switch (state) {
                case 1:
                    // We've sent our request...
                    m = line.match(/%START.*\s([0-9]+)-([0-9]+)/);
                    if (m) {
                        console.log('Getting updates for ' + dbName);
                        state = 2;
                    } else {
                        console.log('ERR ' + dbName + ' (1) > ' + line);
                    }
                    return;
                case 2:
                    // Receiving updates...
                    if (line.length > 0 && line[0] == '%') {
                        if (line.substring(0, 4) == '%END') {
                            console.log('End of update. ' + dbName + ' @ ' + latestSerial + '; ' + entriesAdded + ' added, ' + entriesDeleted + ' deleted');
                            client.end();
                            databases[dbName].serial = latestSerial;
                            if (startSerial != latestSerial) {
                                self.exportDB(dbName);
                            }
                            state = 0;
                            return;
                        } else {
                            console.log('Unknown error message? >' + line);
                        }
                    }
                    m = line.match(/^(ADD|DEL)\s([0-9]+)$/);
                    if (m) {
                        if (m[1] == 'ADD') { entriesAdded++; } else { entriesDeleted++; }
                        // console.log(dbName + ': SERIAL ' + m[2] + ' ACTION: ' + m[1]);
                        latestSerial = parseInt(m[2], 10);
                        action = m[1];
                        state = 3;
                    } else {
                        // console.log('ERR ' + dbName + ' (2) > ' + line);
                    }
                    return;
                case 3:
                    if (line !== '') {
                        packet.push(line);
                    } else if (packet.length > 0) {
                        if (latestSerial > startSerial) {
                            // console.log('Processing packet.');
                            self.parsePacket(packet, dbName, (action == 'DEL') ? true : false);
                        } else {
                            // console.log('Skipping ' + latestSerial);
                        }
                        packet = [];
                        state = 2;
                    } else {
                        // Ignoring empty line at the beginning?!
                    }
                    break;
            }
        };
        state = 1;
        var buf = '';
        client.on('data', function(data) {
            buf += data;
            while (true) {
                var m = buf.match(/^([^\n\r]*)\r?\n/);
                if (!m) break;
                buf = buf.substring(m[0].length);
                process(m[1]);
            }
        });
        write('-g ' + curDB.intName + ':3:' + databases[dbName].serial + '-LAST');
    });
    client.on('error', function() {
        console.log('Realtime failed for', dbName);
        setTimeout(function() {
            console.log('Retrying realtime for', dbName);
            self.enableRT(dbName);
        }, 60 * 1000);
    });
};

TinyIRRDBCache.prototype.getDump = function(dbName) {
    var self = this;
    console.log('Trying to get a fresh dump for ' + dbName);
    if (!this.config.databases[dbName].dump) {
        console.log('Could not get dump for ' + dbName + '. No dump-address given.');
        return;
    }
    var scurl = spawn('curl', [this.config.databases[dbName].serial]);
    var serial = '';
    scurl.stdout.on('data', function(data) {
        serial += data;
    });
    scurl.on('close', function() {
        if (serial === '') {
            console.log('Got no serial for ' + dbName + '; Skipping this database.');
            return;
        }
        databases[dbName] = { serial: parseInt(serial, 10), macros: {}, asnv4: {}, asnv6: {}, prefixes: {}, pc: 0, mc: 0 };
        var sdump = spawn('curl', [self.config.databases[dbName].dump]);
        if (self.config.databases[dbName].dump.match(/\.gz/)) {
            var gzip = zlib.createGunzip();
            sdump.stdout.pipe(gzip);
            self.loadStream(dbName, gzip);
        } else {
            self.loadStream(dbName, sdump.stdout);
        }
    });
};

TinyIRRDBCache.prototype.loadStream = function(dbName, stream) {
    var buf = '';
    var x = 0;
    var packet = [];
    var self = this;
    stream.on('data', function(data) {
        buf += data;
        while (true) {
            var m = buf.match(/^([^\n\r]*)\r?\n/);
            if (!m) break;
            buf = buf.substring(m[0].length);
            if (m[1] === '') {
                x++;
                self.parsePacket(packet, dbName);
                if (x % 10000 === 0) console.log(process.memoryUsage().heapUsed + '; ' + databases[dbName].pc + '; ' + databases[dbName].mc);
                packet = [];
            } else {
                packet.push(m[1]);
            }
        }
    });
    stream.on('end', function() {
        self.exportDB(dbName);
    });
};

TinyIRRDBCache.prototype.loadFromFile = function(file, dbName, serial) {
    if (!databases[dbName]) databases[dbName] = { serial: serial, macros: {}, asnv4: {}, asnv6: {}, prefixes: {}, pc: 0, mc: 0 };
    var self = this;
    file = fs.createReadStream(file);
    var gzip = zlib.createGunzip();
    file.pipe(gzip);
    this.loadStream(dbName, gzip);
};

TinyIRRDBCache.prototype.importDB = function(dbName, cb) {
    fs.readFile('/tmp/' + dbName + '.tiny', function(err, buf) {
        if (err) {
            if (cb) cb(err);
            return;
        }
        var offs = 0;
        var magic = buf.toString('binary', offs, offs + 4); offs += 4;
        if (magic != 'ECXD') {
            console.log('Not a TinyIRRDBCache db file.');
            console.log(magic);
            if (cb) cb(err);
            return;
        }
        databases[dbName] = { serial: buf.readUInt32BE(offs), macros: {}, asnv4: {}, asnv6: {}, prefixes: {} };
        offs += 4;
        var tmpType = 0;
        var tmpLen = 0;
        var tmpStr = '';
        var asn, asnCount, arr, j, x;
        while (true) {
            tmpLen = buf.readUInt32BE(offs);
            if (tmpLen === 0) break;
            offs += 4;
            tmpType = buf.readUInt8(offs); offs++;
            switch (tmpType) {
                case 1:
                    var tmpX = buf.readUInt16BE(offs); offs += 2;
                    var tmpMacro = buf.toString('binary', offs, offs + tmpX); offs += tmpX;
                    tmpX = buf.readUInt32BE(offs); offs += 4;
                    var tmpContent = buf.toString('binary', offs, offs + tmpX); offs += tmpX;
                    databases[dbName].macros[tmpMacro] = JSON.parse(tmpContent);
                    break;
                case 2:
                    asn = buf.readUInt32BE(offs); offs += 4;
                    asnCount = buf.readUInt32BE(offs); offs += 4;
                    arr = [];
                    for (j = 0; j < asnCount; j++) {
                        x = new Buffer(5);
                        buf.copy(x, 0, offs, offs + 5); offs += 5;
                        var ipIn = v42str(x);
                        repairV4(x);
                        var ipOut = v42str(x);
                        if (ipIn != ipOut) {
                            console.log(ipIn + ' > ' + ipOut);
                        }
                        arr.push(x);
                    }
                    databases[dbName].asnv4[asn] = arr;
                    break;
                case 3:
                    asn = buf.readUInt32BE(offs); offs += 4;
                    asnCount = buf.readUInt32BE(offs); offs += 4;
                    arr = [];
                    for (j = 0; j < asnCount; j++) {
                        x = new Buffer(17);
                        buf.copy(x, 0, offs, offs + 17); offs += 17;
                        repairV6(x);
                        arr.push(x);
                    }
                    databases[dbName].asnv6[asn] = arr;
                    break;
            }
        }
        console.log('Import done; ' + dbName + ' @ ' + databases[dbName].serial);
        console.log(process.memoryUsage().heapUsed);
        if (cb) cb(null);
    });
};

// Write a database to a file for quick import
TinyIRRDBCache.prototype.exportDB = function(dbName) {
    var bufSize = 1024 * 1024 * 20; // 20 Megs should be okay
    var buf = new Buffer(bufSize);
    var offs = 0;
    var tmpSize = 0;
    var tmpStr = '';
    var asnBase, asn;
    var j = 0;

    buf.write('ECXD', 0); offs += 4;
    buf.writeUInt32BE(databases[dbName].serial, offs); offs += 4;

    for (var macro in databases[dbName].macros) {
        tmpStr = JSON.stringify(databases[dbName].macros[macro]);
        tmpSize = 1 + 2 + macro.length + 4 + tmpStr.length;
        buf.writeUInt32BE(tmpSize, offs); offs += 4;
        buf.writeUInt8(1, offs); offs += 1;
        buf.writeUInt16BE(macro.length, offs); offs += 2;
        buf.write(macro, offs, macro.length, 'binary'); offs += macro.length;
        buf.writeUInt32BE(tmpStr.length, offs); offs += 4;
        buf.write(tmpStr, offs, tmpStr.length, 'binary'); offs += tmpStr.length;
    }
    asnBase = databases[dbName].asnv4;
    for (asn in asnBase) {
        tmpSize = 1 + 4 + 4 + asnBase[asn].length * 5;
        buf.writeUInt32BE(tmpSize, offs); offs += 4;
        buf.writeUInt8(2, offs); offs += 1;
        buf.writeUInt32BE(asn, offs); offs += 4;
        buf.writeUInt32BE(asnBase[asn].length, offs); offs += 4;
        for (j = 0; j < asnBase[asn].length; j++) {
            asnBase[asn][j].copy(buf, offs, 0, 5); offs += 5;
        }
    }
    asnBase = databases[dbName].asnv6;
    for (asn in asnBase) {
        tmpSize = 1 + 4 + 4 + asnBase[asn].length * 17;
        buf.writeUInt32BE(tmpSize, offs); offs += 4;
        buf.writeUInt8(3, offs); offs += 1;
        buf.writeUInt32BE(asn, offs); offs += 4;
        buf.writeUInt32BE(asnBase[asn].length, offs); offs += 4;
        for (j = 0; j < asnBase[asn].length; j++) {
            asnBase[asn][j].copy(buf, offs, 0, 17); offs += 17;
        }
    }

    buf.writeUInt32BE(0, offs); offs += 4;
    fs.writeFile('/tmp/' + dbName + '.tiny', buf.slice(0, offs));
    console.log('Exported ' + dbName);
};

TinyIRRDBCache.prototype.parsePacket = function(packet, dbName, remove) {
    var prefix = '';
    var macro = '';
    var type = 0;
    var asn = '';
    var members = [];
    var lastType = '';
    for (var j = 0; j < packet.length; j++) {
        var m = packet[j].match(/^([^\s:]*):([^#]*)(#.*)?$/);
        if (!m) {
            m = ['', lastType, packet[j].trim()];
        }
        lastType = m[1];
        switch (m[1]) {
            case 'as-set':
                if (j !== 0) continue;
                macro = m[2].trim().toUpperCase();
                type = 1;
                break;
            case 'route':
                if (j !== 0) continue;
                prefix = m[2].trim();
                type = 2;
                break;
            case 'route6':
                if (j !== 0) continue;
                prefix = m[2].trim();
                type = 3;
                break;
            case 'members':
                var members2 = m[2].trim().split(',');
                for (var i = 0; i < members2.length; i++) {
                    var member = members2[i].trim().toUpperCase();
                    if (member !== '') members.push(member);
                }
                break;
            case 'origin':
                asn = parseInt(m[2].trim().substring(2), 10);
                break;
        }
    }
    if (type == 2) {
        // Prefix...
        //console.log(asn + ' => ' + prefix);
        this.updatePrefix(prefix, asn, dbName, remove);
    } else if (type == 3) {
        // Prefix...
        //console.log(asn + ' => ' + prefix);
        this.updatePrefix(prefix, asn, dbName, remove);
    } else if (type == 1) {
        if (remove) {
            if (databases[dbName].macros[macro]) {
                databases[dbName].mc--;
                delete databases[dbName].macros[macro];
            } else {
                console.log('Trying to delete non-existing macro: ' + macro + '. Inconsistency?!');
            }
        } else {
            databases[dbName].mc++;
            databases[dbName].macros[macro] = members;
        }
    }
};

TinyIRRDBCache.prototype.updatePrefix = function(prefix, asn, dbName, remove) {
    var ip = str2ip(prefix);
    var asnBase = (ip.length > 5) ? databases[dbName].asnv6 : databases[dbName].asnv4;
    if (!asnBase[asn]) asnBase[asn] = [];
    if (remove) {
        // Compare prefix with all existing ones. This is actually pretty
        // expensive and maybe should be done in another fashion... :/
        var found = false;
        for (var j = 0; j < asnBase[asn].length; j++) {
            var buf = asnBase[asn][j];
            if (buf.toString('hex') == ip.toString('hex')) continue;
            asnBase[asn].splice(j, 1);
            found = true;
            break;
        }
        if (!found) {
            console.log('Deleted prefix not found: ' + asn + ' -> ' + prefix);
        }
    } else {
        databases[dbName].pc++;
        asnBase[asn].push(ip);
    }
};

TinyIRRDBCache.prototype.generatePrefixList = function() {
    var countv4 = 0, countv6 = 0, i = 0;
    var asn, dbName, j;
    for (dbName in databases) {
        for (asn in databases[dbName].asnv4) {
            countv4 += databases[dbName].asnv4[asn].length;
        }
        for (asn in databases[dbName].asnv6) {
            countv6 += databases[dbName].asnv6[asn].length;
        }
    }
    var prefixesv4 = new Buffer(countv4 * 9);
    var prefixesv6 = new Buffer(countv6 * 21);
    var pc4 = 0;
    var pc6 = 0;
    for (dbName in databases) {
        for (asn in databases[dbName].asnv4) {
            for (j = 0; j < databases[dbName].asnv4[asn].length; j++) {
                databases[dbName].asnv4[asn][j].copy(prefixesv4, pc4 * 9);
                prefixesv4.writeUInt32BE(asn, pc4 * 9 + 5);
                pc4++;
            }
        }
        for (asn in databases[dbName].asnv6) {
            for (j = 0; j < databases[dbName].asnv6[asn].length; j++) {
                databases[dbName].asnv6[asn][j].copy(prefixesv6, pc6 * 21);
                prefixesv6.writeUInt32BE(asn, pc6 * 21 + 17);
                pc6++;
            }
        }
    }
    // Bubblesort...
    var n = pc4, newn;
    var tmpBuf = new Buffer(9);
    while (n > 1) {
        newn = 1;
        for (i = 0; i < n - 1; ++i) {
            if (prefixesv4[i * 9 + 4] > prefixesv4[(i + 1) * 9 + 4]) {
                prefixesv4.copy(tmpBuf, 0, i * 9, i * 9 + 9);
                prefixesv4.copy(prefixesv4, i + 9, (i + 1) * 9, (i + 1) * 9 + 9);
                tmpBuf.copy(prefixesv4, (i + 1) * 9, 0, 9);
            }
        }
        n = newn;
    }

    n = pc6;
    tmpBuf = new Buffer(21);
    while (n > 1) {
        newn = 1;
        for (i = 0; i < n - 1; ++i) {
            if (prefixesv6[i * 21 + 16] > prefixesv6[(i + 1) * 21 + 16]) {
                prefixesv6.copy(tmpBuf, 0, i * 21, i * 21 + 21);
                prefixesv6.copy(prefixesv6, i + 21, (i + 1) * 21, (i + 1) * 21 + 21);
                tmpBuf.copy(prefixesv6, (i + 1) * 21, 0, 21);
            }
        }
        n = newn;
    }

    fs.writeFile('/tmp/prefixes4', prefixesv4);
    fs.writeFile('/tmp/prefixes6', prefixesv6);
};


var lookupMacro = function(asnBase, dbName, macro, result, onPrefix) {
    if (!databases[dbName].macros[macro]) {
        // console.log('Macro not found: ' + macro);
        return;
    }
    for (var i = 0; i < databases[dbName].macros[macro].length; i++) {
        var m = databases[dbName].macros[macro][i].match(/^AS([0-9]+)$/i);
        if (!m) {
            // Should be another macro
            if (result.macros.indexOf(databases[dbName].macros[macro][i]) < 0) {
                // console.log('New other macro: ' + databases[dbName].macros[macro][i]);
                result.macros.push(databases[dbName].macros[macro][i]);
                lookupMacro(asnBase, dbName, databases[dbName].macros[macro][i], result, onPrefix);
            }
        } else {
            var asn = parseInt(m[1], 10);
            if (asnBase[asn]) {
                onPrefix(asnBase[asn]);
                // result.prefixes = result.prefixes.concat(asnBase[asn]);
            } else {
                // console.log('AS not found: ' + asn);
            }
        }
    }
};

var resolveMacro = function(dbName, macro, result, globalResult) {
    if (!databases[dbName].macros[macro]) {
        // console.log('Macro not found: ' + macro);
        return;
    }
    for (var i = 0; i < databases[dbName].macros[macro].length; i++) {
        var m = databases[dbName].macros[macro][i].match(/^AS([0-9]+)$/i);
        if (!m) {
            // Should be another macro
            if (result.macros.indexOf(databases[dbName].macros[macro][i]) < 0) {
                result.macros.push(databases[dbName].macros[macro][i]);
                resolveMacro(dbName, databases[dbName].macros[macro][i], result, globalResult);
            }
        } else {
            var asn = parseInt(m[1], 10);
            if (result.asn.indexOf(asn) < 0) result.asn.push(asn);
            if (globalResult.asn.indexOf(asn) < 0) globalResult.asn.push(asn);
        }
    }
};


var server = http.createServer(function(req, res) {
    if (req.url == '/') {
        res.end('see the source code on the serving machine at ' + process.argv[1] + ' for usage details. (Or see the README)');
        return;
    }

    if (req.url == '/wp') {
        x.generatePrefixList();
        res.end('regenerating prefix list');
        return;
    }

    if (req.url == '/dump') {
        console.log('dumping db');
        res.write(JSON.stringify(databases, null, 2));
        res.end();
        return;
    }

    var url = req.url.match(/^\/(.*)\/(.*)\/v(4|6)/);
    if (!url) {
        res.end();
        return;
    }

    var result = { prefixes: [], macros: [] };
    var macros = [];
    console.log('Looking up ' + url[1]);
    if (!databases[url[1]]) {
        res.end('Database not found.');
        return;
    }
    var v6 = (url[3] == '4') ? false : true;
    var asnBase = (url[3] == '4') ? databases[url[1]].asnv4 : databases[url[1]].asnv6;

    if (asnBase[url[2]]) {
        res.end(JSON.stringify(asnBase[url[2]]));
        return;
    }

    var i = 0;
    res.write('{"prefixes":[');
    lookupMacro(asnBase, url[1], url[2], result, function(prefixes) {
        var j = 0;
        if (v6) {
            for (j = 0; j < prefixes.length; j++) {
                if (i > 0) res.write(',');
                res.write('"' + v62str(prefixes[j]) + '"');
                i++;
            }
        } else {
            for (j = 0; j < prefixes.length; j++) {
                if (i > 0) res.write(',');
                res.write('"' + prefixes[j][0] + '.' + prefixes[j][1] + '.' + prefixes[j][2] + '.' + prefixes[j][3] + '/' + prefixes[j][4] + '"');
                i++;
            }
        }
    });
    res.write('],"macros":[');
    if (result.macros.length > 0) {
        res.write('"' + result.macros.join('","') + '"');
    }
    res.write('],"prefixCount":' + i + '}');
    res.end();

}).listen(8086, '0.0.0.0'); //FIXME, hardcoded listen address and port

var x = new TinyIRRDBCache(config, databases);
x.init();

console.log('Online.');

// drop privileges when run as root
if (process.getuid() == 0) {
    process.nextTick(function() {
        process.setgid('nobody');
        process.setuid('nobody');
    });
}
