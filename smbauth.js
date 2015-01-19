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

module.exports.SMBAuth = function(sock) {
    this.state = 0;
    this.authenticated = false;
    this.uid = 2400;

    this.respond = function(packet) {
        try {
            switch(this.state) {
            case 0:
                var response = this.negotiate(new SMBPacket(packet));
                this.state = 1;
                break;
            case 1:
                var response = this.challenge(new SMBPacket(packet));
                this.state = 2;
                break;
            case 2:
                var response = this.success(new SMBPacket(packet));
                this.state = 3;
                this.authenticated = true;
                break;
            case 3:
                out.red("SMB Auth is not supposed to receive more packets!");
                return;
            default:
                out.red("Unknown FSM state");
            }
            var nbt = new Buffer(4);
            nbt.writeUInt32BE((response.length) & 0x0fff, 0);
            sock.write(Buffer.concat([nbt,response]));
        } catch(e) {
            out.red("Error in SMB authentication");
            out.red(e);
            if(sock) sock.end();
        }
    }

    this.set_uid = function(val) {
        this.uid = val;
    }

    //
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

    //
    // After negotiating the protocol version, the client initiates
    // authentication.  We need to provide a server challenge so that
    // the client can put together a "security blob" for us.
    //

    this.challenge = function(packet) {
        var header = packet.smb_header;
        header[9] = packet.smb_flags | 0x80;
        header.writeUInt32LE(0xc0000016, 5);
        header.writeUInt16LE(this.uid, 28);
        var body = new Buffer("04ff00fa0100004301cf01a182013f30" +
                              "82013ba0030a0101a10c060a2b060104" +
                              "01823702020aa2820124048201204e54" +
                              "4c4d53535000020000001a001a003800" +
                              "000015828962f153d2ccced2d8130000" +
                              "000000000000ce00ce00520000000601" +
                              "b11d0000000f53004e00410052004600" +
                              "49004e0047005f004d00490054004d00" +
                              "02001a0053004e004100520046004900" +
                              "4e0047005f004d00490054004d000100" +
                              "14004a004f005300480053002d005400" +
                              "34003200300004002200740072006100" +
                              "63006500730065006300750072006900" +
                              "740079002e0063006f006d0003003800" +
                              "4a004f005300480053002d0054003400" +
                              "320030002e0074007200610063006500" +
                              "73006500630075007200690074007900" +
                              "2e0063006f006d000500220074007200" +
                              "61006300650073006500630075007200" +
                              "6900740079002e0063006f006d000700" +
                              "08001c959e4cb15acf01000000005300" +
                              "6e0061007200660000004a006f007300" +
                              "6800200053002e002000260020005600" +
                              "6900630074006f00720020004d002e00" +
                              "0000", "hex");
        body.writeUInt16LE(body.length-11, 9);
        return Buffer.concat([header, body]);
    }

    //
    // Once the client has been challenged, we will need to respond
    // saying that we accept the credentials.  Obviously, we don't
    // really care what the credentials are at all -- once this is
    // done, the client will believe there is an open SMB channel, and
    // will likely do a TREE_CONNECT.
    //

    this.success = function(packet) {
        var header = packet.smb_header;
        header[9] = packet.smb_flags | 0x80;
        header.writeUInt32LE(0, 5);
        header.writeUInt16LE(this.uid, 28);

        var body = new Buffer("04ff00c000000009009500a1073005a0" +
                              "030a010053006e006100720066000000" +
                              "4a006f0073006800200053002e002000" +
                              "2600200056006900630074006f007200" +
                              "20004d002e000000", "hex");

        body.writeUInt16LE(body.length-11, 9);
        return Buffer.concat([header, body]);
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
