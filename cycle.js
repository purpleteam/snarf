//
// snarf - SMB man-in-the-middle tool
// Copyright (C) 2015 Josh Stone (yakovdk@gmail.com)
//                    Victor Mata (victor@offense-in-depth.com)
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//
// ------------------------------------------------------------------------

var out = require("./out.js");
var RL  = require('readline');
var fs  = require('fs');

module.exports.Cycle = function() {
    var contents = [];
    var cursor  = 0;
    var count = 0;
    var enabled = true;

    this.push = function(x) {
        count += 1;
        contents[count-1] = x;
    }

    // use strict comparison; remove all elements as
    // duplicates may exist
    this.pop = function(x) {
        for(var i = 0; i < contents.length; i++) {
            if(contents[i] === x) {
                contents.splice(i, 1);
                count = count - 1;
            }
        }
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

    this.list = function() {
        return contents;
    }
}

module.exports.loadCycle = function(file) {
    var list = new module.exports.Cycle();
    RL.createInterface({
        input: fs.createReadStream(file),
        terminal: false
    }).on('line', function(line){
        list.push(line);
    });
    return list;
}
