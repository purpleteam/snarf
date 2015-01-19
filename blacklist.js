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

    // use index to remove first element since there should be
    // no duplicates in the array
    this.pop = function(x) {
        index = hosts.indexOf(x);
        if(index > -1) {
            hosts.splice(index, 1);
            count = count - 1;
        }
    }

    this.ok = function(x) {
        return hosts.indexOf(x) < 0;
    }

    this.list = function() {
        return hosts;
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
