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

var express = require("express");
var md = require("marked");
var fs = require("fs");
var out = require("./out.js");

module.exports.ControlPanel = function(broker, port, globals) {

    var app = express();
    app.engine(".html", require("ejs").__express);
    app.set("views", __dirname + "/html");
    app.set("view engine", "html");
    app.use(express.static(__dirname + "/static"));

    app.set("tab_active", false);
    app.set("refresh_active", false);
    app.set("refresh_count", 5000);

    app.get('/', function(req, res){
        var middlers  = broker.listMiddlers();
        var current   = broker.getCurrentID();
        var target    = globals.target;
        var blacklist = globals.blacklist.list();
        res.render('index', { middlers:     broker.listMiddlers(),
                              current:      broker.getCurrentID(),
                              target:       globals.targetpeek ? globals.targetpeek() : globals.target(),
                              targetsingle: globals.targetsingle,
                              blacklist:    globals.blacklist.list(),
                              targetlist:   globals.cycle.list()
                            });
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

    app.get('/block/add/:addr', function(req, res) {
        var addr = req.params.addr;
        out.yellow("[DEBUG] Control Server: Received request to block: " + addr);
        for(var i = 0; i < broker.getMiddlers().length; i++) {
            if(broker.getMiddlers()[i].getClientAddr() == addr) {
                broker.getMiddlers()[i].terminate();
            }
        }
        broker.resetIDs();
        if(globals.blacklist.ok(addr)) {
            globals.blacklist.push(addr);
        }
        res.redirect('/');
    });

    app.get('/block/remove/:addr', function(req, res) {
        var addr = req.params.addr;
        out.yellow("[DEBUG] Control Server: Received request to unblock: " + addr);
        globals.blacklist.pop(addr);
        res.redirect('/');
    });

    app.patch('/set/target/:addr', function(req, res) {
        var addr = req.params.addr;
        if(!globals.targetpeek) {
            out.blue("Setting new default IP to " + addr);
            globals.target = function() { return addr };
        }
        res.redirect(301, "/");
    });

    app.get('/target/mode/cycle', function(req, res) {
        out.yellow("[DEBUG] Control Server: Received request to switch mode to cycle");
        if(globals.cycle.list().length > 0) {
            globals.targetsingle = false;
            globals.target       = function() { return globals.cycle.shift() }
            globals.targetpeek   = function() { return globals.cycle.current() }
        } else {
          out.yellow("[DEBUG] Control Server: Cycle list is empty!")
        }
        res.redirect('/');
    });

    app.get('/target/mode/single/:addr', function(req, res) {
        var addr = req.params.addr;
        out.yellow("[DEBUG] Control Server: Received request to switch mode to single : " + addr);
        if(addr) {
            globals.targetsingle = true;
            globals.target       = function() { return addr }
            // This doesnt play nice wih line 45
            // globals.targetpeek   = function() { return false }
            globals.targetpeek   = undefined;
            out.yellow("[DEBUG] Control Server: Successfully entered single target mode")
        } else {
            // The client-side error handling should catch non-submitted data,
            // but lets keep this here just in case
            addr = globals.targetinit();
            out.yellow("[DEBUG] Control Server: undefined detected, resetting value to initial target: " + addr);
        }
        res.redirect('/');
    });

    app.get('/target/add/:addr', function(req, res) {
        var addr = req.params.addr;
        out.yellow("[DEBUG] Control Server: Received request to add target to cycle list: " + addr);
        globals.cycle.push(addr);
        res.redirect('/');
    });

    app.get('/target/remove/:addr', function(req, res) {
        var addr = req.params.addr;
        out.yellow("[DEBUG] Control Server: Received request to remove target to cycle list: " + addr);
        globals.cycle.pop(addr);
        res.redirect('/');
    });

    app.get('/set/tab', function(req, res) {
        if(!app.get("tab_active")) {
            app.set("tab_active", "0");
        } else {
            app.set("tab_active", false);
        }
        out.yellow("[DEBUG] Control Server: tab_active is now set to: " + app.get("tab_active"));
        res.redirect('/');
    });

    app.get('/refresh/:num', function(req, res) {
        var n = parseInt(req.params.num);
        if(n != NaN) {
            if(n > 0) {
                app.set("refresh_count", n);
                app.enable("refresh_active");
            } else {
                app.disable("refresh_active");
            }
        } else {
            app.disable("refresh_active");
        }
        out.yellow("[DEBUG] Control Server: refresh_active is: " + app.get("refresh_active") + " and time is: " + app.get("refresh_count"));
        res.redirect('/');
    });

    app.listen(port, '127.0.0.1');
    out.blue("Created control server, direct browser to http://localhost:" + port + "/");
}
