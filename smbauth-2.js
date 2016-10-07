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
// This module implements a small state machine to carry out SMB
// authentication.  The original design would reuse the authentication
// packets processed at the beginning of the victim's communication
// with the middled server.
//
// This usually would work, but occasionally issues were encountered
// during penetration tests.  As one may imagine, the worst time to
// realize that a proxied authentication won't work is when you have a
// live connection you want to use in an actual attack.  *sigh*.
//
// This approach performs a net-new authentication for the in-bound
// hacker tool so that we can guarantee that it will be able to
// connect.
//
// BTW, yes this uses some big binary blobs -- the strangest oddity is
// that you will se a timestamp recorded during development.  Maybe
// that's some really twisted form of documentation of our development
// schedule ;-).
//
//

var net = require('net');
var out = require('./out.js');

//
// Parse an SMB packet so we have various fields available.  In the
// future, we should merge this with what's in the smb.js module,
// since it probably overlaps substantially.
//

SMBPacket = function(packet) {
    this.nbt_msg       = packet.readUInt8(0);
    this.nbt_len       = packet.readUInt32LE(0) & 0x0fff;
    this.smb_body      = packet.slice(4, packet.length);
    this.bodylen       = this.smb_body.length;
    this.smb_header    = this.smb_body.slice(0,32);
    this.smb_component = this.smb_body.slice(0,4);
    this.smb_command   = this.smb_body.readUInt8(4);
    this.smb_status    = this.smb_body.readUInt32LE(5);
    this.smb_flags     = this.smb_body.readUInt8(9);
    this.smb_flags2    = this.smb_body.readUInt16LE(10);
    this.smb_pidh      = this.smb_body.readUInt16LE(12);
    this.smb_sig       =
        this.smb_body.readUInt32LE(14) << 32 +
        this.smb_body.readUInt32LE(18);
    this.smb_res       = this.smb_body.readUInt16LE(22);
    this.smb_tree      = this.smb_body.readUInt8(24);
    this.smb_pid       = this.smb_body.readUInt16LE(25);
    this.smb_uid       = this.smb_body.readUInt16LE(27);
    this.smb_mid       = this.smb_body.readUInt16BE(29);
    this.smb_rest      = this.smb_body.slice(31,this.bodylen);
    this.rest_len      = this.smb_rest.length;
}

//
// This is a state machine with functions that generate appropriate
// responses to inbound SMB requests from the hacker tool who will be
// inserted into existing connections.
//
// This code used to fake some NTLMSSP authentication, so you could just
// login with any username or password you want.  But then, Arno0x informed
// us on Github that newere Samba versions actually check the values in
// the NTLMSSP response, so we've rethought.  This state machine now
// assumes that the user will authenticate to the local middler using an
// anonymous session (in Samba terms, this is username "" and password "").
// This should then work to authenticate without having to worry about the
// NTLMSSP negotiation.
//

module.exports.SMBAuth = function(sock) {
    this.state = 0;
    this.authenticated = false;
    this.uid = 2400;

    this.respond = function(packet) {
	out.green("AUTH received packet!");
	try {
	    switch(this.state) {
	    case 0:
		var response = this.negotiate(new SMBPacket(packet));
		this.state = 1;
		break;
	    case 1:
		var response = this.setup_anon(new SMBPacket(packet));
		this.state = 2;
		this.authenticated = true;
		break;
	    case 2:
		out.red("SMB Auth is not supposed to receive more packets!");
		return;
	    default:
		out.red("Unknown SMB Auth State!");
	    }
            var nbt = new Buffer(4);
            nbt.writeUInt32BE((response.length) & 0x0fff, 0);
            sock.write(Buffer.concat([nbt,response]));
	} catch(e) {
	    out.red("Error in SMB Authentication");
	    out.red(e);
	    if(sock) sock.end();
	}
    }

    this.set_uid = function(val) {
        this.uid = val;
    }

    //
    // This is a correct response to an anonymous authentication attempt.
    // Hopefully this will cause fewer problems than the previous iteration,
    // which faked a whole NTLMSSP negotiation.
    //
    
    this.setup_anon = function(packet) {
	var header = packet.smb_header;
	header[9] = packet.smb_flags | 0x80;
	header.writeUInt32LE(0, 5);
	header.writeUInt16LE(this.uid, 28);

	var body = new Buffer("03ff00c9000000a00011570069006e00" +
			      "64006f00770073002000370020005000" +
			      "72006f00660065007300730069006f00" +
			      "6e0061006c0020003700360030003100" +
			      "20005300650072007600690063006500" +
			      "20005000610063006b00200031000000" +
			      
			      // SMB banner, currently says:
			      //
			      // Snarf, Anonymous Auth Only
			      //
			      "53006e006100720066002c0020004100" +
			      "6e006f006e0079006d006f0075007300" +
			      "2000410075007400680020004f006e00" +
			      "6c0079000000" +

			      "57004f0052004b004700" +
			      "52004f005500500000", "hex");

	body.writeUInt16LE(body.length - 11, 9);
	return Buffer.concat([header, body]);
    }

    // The first request the client sends is a NEGOTIATE.  This
    // informs the server what protocol variants are supported.  In
    // response, we always ask for NTLM authentication.
    //

    this.negotiate = function(packet) {
        this.dialects = [];
        var buffer = packet.smb_rest.slice(4, packet.rest_len);
        var dialect = 1;
        var index = 0;
        for(var cursor = 0; cursor < buffer.length; cursor++) {
            if(buffer[cursor] == 0) {
                var str = buffer.toString("utf8", dialect, cursor);
                if(str == "NT LM 0.12") index = this.dialects.length;
                this.dialects.push(str);
                dialect = cursor + 2;
            }
        }
        var header = packet.smb_header;
        header[9] = [packet.smb_flags | 0x80];
        var body = new Buffer("11090003320001000411000000000100" +
                              "00000000fce30180ea1f9e4cb15acf01" +
                              "2c010088003178a5db280d8744a8d124" +
                              "0e69bb441e607606062b0601050502a0" +
                              "6c306aa03c303a060a2b060104018237" +
                              "02021e06092a864882f7120102020609" +
                              "2a864886f712010202060a2a864886f7" +
                              "1201020203060a2b0601040182370202" +
                              "0aa32a3028a0261b246e6f745f646566" +
                              "696e65645f696e5f5246433431373840" +
                              "706c656173655f69676e6f7265", "hex");
        body.writeUInt16LE(index, 1);
        return Buffer.concat([header,body]);
    }
}

//
// This is proof-of-concept script code here.  This will run a little
// featureless SMB server.  You can test auth with something like
// this:
//
//    $ sudo node -e "require('./auth.js').test()" &
//    $ smbclient -U foo%foo //localhost/c$
//

module.exports.test = function() {
    client = net.createServer(function(sock) {
        out.blue("Socket opened");
        authorizer = new module.exports.SMBAuth(sock);

        sock.on("data", function(packet) {
            if(!authorizer.authenticated) {
                authorizer.respond(packet);
            } else {
                // handle it normally
                out.red("received a packet to send to the middler!");
            }
        });

        sock.on("end", function() {
            out.blue("Socket closed.");
        });
    });

    client.listen(445, "0.0.0.0", function() {
        out.blue("Server bound on port 445");
    });
}
