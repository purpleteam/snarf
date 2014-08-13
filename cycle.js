var out = require("./out.js");
var RL  = require('readline');
var fs  = require('fs');

module.exports.Cycle = function() {
    var contents = [];
    var cursor  = 0;
    var count = 0;
    
    this.push = function(x) {
        count += 1;
        contents[count-1] = x;
    }
    
    this.current = function() {
        return contents[cursor];
    }

    this.next = function() {
        cursor = (cursor + 1) % count;
    }        

    this.shift = function() {
        var ret = this.current();
        this.next();
        out.red("Returning " + ret);
        return ret;
    }
}

module.exports.fromFile = function(file) {
    var list = new module.exports.Cycle();
    RL.createInterface({
        input: fs.createReadStream(file),
        terminal: false
    }).on('line', function(line){
        list.push(line);
    });
    return list;
}
