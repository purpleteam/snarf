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

var moment = require("moment");

function color(text, color) {
    console.log(moment().format("HH:mm:ss") + " \x1b[%d;1m%s\x1b[0m", color, text);
}

function dim(text, color) {
    console.log(moment().format("HH:mm:ss") + " \x1b[%dm%s\x1b[0m", color, text);
}

module.exports.red = function(text) {
    color(text, 31);
}

module.exports.green = function(text) {
    color(text, 32);
}

module.exports.darkgreen = function(text) {
    dim(text, 32);
}

module.exports.yellow = function(text) {
    color(text, 33);
}

module.exports.blue = function(text) {
    color(text, 34);
}

module.exports.magenta = function(text) {
    color(text, 35);
}

module.exports.cyan = function(text) {
    color(text, 36);
}

module.exports.white = function(text) {
    color(text, 37);
}
