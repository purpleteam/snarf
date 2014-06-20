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

var express = require("express");
var md = require("marked");
var fs = require("fs");
var out = require("./out.js");

module.exports.ControlPanel = function(broker, port) {

    var app = express();
    app.engine(".html", require("ejs").__express);
    app.set("views", __dirname + "/html");
    app.set("view engine", "html");
    app.use(express.static(__dirname + "/static"));
    
    app.get('/', function(req, res){
	var middlers = broker.listMiddlers();
	var current  = broker.getCurrentID();
	res.render('index', { middlers: broker.listMiddlers(),
			      current:  broker.getCurrentID() });
    });

    app.get('/kill/:num', function(req, res) {
 	var n = parseInt(req.params.num);
 	out.blue("Control Server: Killing session #"+n);
 	if(n != NaN && broker.getMiddlers().length > n) {
 	    broker.getMiddlers()[n].terminate();
 	    broker.resetIDs();
 	}
	res.redirect('/');
    });

    app.get('/choose/:num', function(req, res) {
 	var n = parseInt(req.params.num);
 	out.blue("Control Server: Received choose request for #"+n);
 	if(n != NaN && broker.getMiddlers().length > n) {
 	    broker.setCurrentMiddler(n);
 	}
	res.redirect('/');
    });

    app.get('/expire/:num', function(req, res) {
	var n = parseInt(req.params.num);
	out.blue("Control Server: Received expire request for #" + n);
	if(n != NaN && broker.getMiddlers().length > n) {
	    broker.expire(n);
	}
	res.redirect('/');
    });
    
    app.listen(port);
    out.blue("Created control server, direct browser to http://localhost:" + port + "/");
}