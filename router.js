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
//
// this file presents a module that monitors the kernel log and
// keeps track of all of the routed SMB connections, associating
// them by source/dest IPs/ports.
//

var spawn = require("child_process").spawn;
var exec = require("child_process").exec;
var out = require("./out.js");

module.exports.Router = function(bindip) {
    var klog = spawn("tail", ["-f", "/var/log/kern.log"]);
    var connections = [];

    klog.stdout.on("data", function(x) {
        var lines = x.toString().split(/\n/);
        for(var i = 0; i < lines.length; i++) {
            if(m = lines[i].toString().match(/SRC=([0-9.]+) DST=([0-9.]+) .*?SPT=([0-9]+)/)) {
                var srcip = m[1];
                var dstip = m[2];
                var sport = m[3];
                connections.push([srcip, dstip, sport]);
            }
        }
    });

    // I don't want to be too invasive, but I'll assume that no one
    // already has a "SNARF" chain.  This chain will configure logging
    // and rerouting to the local service.  The user will need to make
    // sure that the traffic they want to intercept gets sent to this
    // chain.

    out.blue("Router: iptables -t nat -X SNARF");
    exec("iptables -t nat -F SNARF", function(a,b,c) {
        out.blue("Router: iptables -t nat -N SNARF");
        exec("iptables -t nat -N SNARF", function(a,b,c) {
            out.blue("Router: iptables -t nat -A SNARF -p tcp -j LOG");
            exec("iptables -t nat -A SNARF -p tcp -j LOG", function(a,b,c) {
                out.blue("Router: iptables -t nat -A SNARF -p tcp --dport 445 -j DNAT --to " + bindip + ":445");
                exec("iptables -t nat -A SNARF -p tcp --dport 445 -j DNAT --to " + bindip + ":445", function(a,b,c) {
                    out.blue("Router: To intercept, run 'iptables -t nat -A PREROUTING -p tcp --dport 445 -j SNARF'");
                });
            });
        });
    });

    function checkout2(srcip, sport, cback, count) {
        var done = false;
        for(var i=0; i<connections.length; i++) {

            if(srcip == connections[i][0] &&
               sport == connections[i][2]) {
                cback(connections[i][1]);
                out.blue("DB hit -- found connection from iptables");
                done = true;
            }
        }
        if(done) { return }
        else {
            out.blue("DB Timeout looking for connection from " + srcip + ":" + sport);

            // this used to be 10, but that seemed to be far longer
            // than necessary after using Snarf in a bunch of
            // pen-tests.  Let's try 5 for awhile.
            if(count > 5) {
                out.blue("DB no response in kernel log, responding with 0.0.0.0");
                cback("0.0.0.0");
            } else {
                setTimeout(checkout2, 100, srcip, sport, cback, count + 1);
            }
        }
    }

    function checkout(srcip, sport, cback) {
        setTimeout(checkout2, 100, srcip, sport, cback, 0);
    }

    this.checkout = checkout;
}
