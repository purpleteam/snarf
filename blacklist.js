var out = require("./out.js");
var RL = require('readline');
var fs = require('fs');

module.exports.Blacklist = function() {
    var hosts = [];
    var count = 0;
    
    this.push = function(x) {
        out.blue("Blacklisting " + x);
        hosts[count] = x;
        count += 1;
    }

    this.ok = function(x) {
        return hosts.indexOf(x) < 0;
    }
}

module.exports.loadBlacklist = function(file) {
    var list = new module.exports.Blacklist();
    RL.createInterface({ 
        input: fs.createReadStream(file),
        terminal: false
    }).on('line', function(line) {
        list.push(line);
    });
    return list;
}

