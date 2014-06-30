snarf
=====

Snarf is a software suite to help increase the value of man-in-the-middle attacks.  Many historical applications of techniques like SMB-Relay rely on assumptions, and relegate these attacks to exploitation, rather than the discovery / enumeration phase of the penetration test.  While Snarf doesn't introduce new vulnerabilities, it does introduce a new capability to capitalize on exploiting familiar vulnerabilities.

Check out [our NOLAcon '14 presentation](http://www.josho.org/software/snarf-nolacon-presentation.pdf) for a decent intro to the concept.

Check out [a 'live' demo of Snarf in action](https://www.youtube.com/watch?v=oBSrcrdRLyA&feature=youtu.be) to get a better sense for how it works.

The Fundamental Idea
====================

At its core, Snarf has one key principle in play: when you MITM something, don't throw it away.  Don't just try to lob a payload through it and hope it works.  Instead, we relay a connection for a client, and keep the connection to the server when the client is done.  We hold onto it, and provide a facility to jack in additional tools to that same, preserved connection.  This way, once we middle a connection, we can explore it.  Use multiple tools, assess what privileges or rights we have, etc. -- all to give the penetration tester more direct control of the situation.

Prerequisites
=============

You will need several key things.  First, Snarf relies on iptables, so it is Linux-specific.  It may be possible to move it to something like PF, but that is currently unknown.  At any rate, here is a list of basic requirements:

  * Linux (Kali works fine)
  * NodeJS -- Snarf is implemented in Node to take advantage of it's snazzy event-driven I/O
  * An existing MITM / redirection strategy -- Snarf will not MITM the victim, it will only capitalize on it
    * ARP poisoning
    * DHCP poisoning
    * LLMNR poisoning
    * ICMP redirect
    * GRE tunnels
    * etc.

In most Linux distributions, the only thing you'll have to do is install Node.  In a Debian-derived distribution, this would look something like this (works in Kali):

    $ sudo apt-get install nodejs

Running Snarf
=============

Here's the basic process:

  1. Do a man-in-the-middle -- Linux must be routing the traffic of your victim
  2. Run Snarf as root, binding to your LAN IP

    $ sudo node snarf.js <bindIP>

  3. Run the iptables rule to move traffic to SNARF's chain:

    $ sudo iptables -t nat -A PREROUTING -p tcp --dport 445 -j SNARF

  3. Open a web browser to http://localhost:4001/
  4. Wait for a connection to come through
  5. Either wait for the connection to "complete" or "expire" it manually with the provided buttons
  6. Connect your own tools (e.g., for SMB use smbclient, net, Metasploit, etc.) to 127.0.0.1.  (Note, the username and password you use don't matter -- Snarf will authenticate it no matter what.  The resulting session will use the snarfed connection to the server and, with it, the victim's credentials)

Known Issues
============

  1. For SMB, Snarf only does username/password auth, not anonymous sessions.  You will want to provide a "-U user%pass" to any Samba-derived tools to make sure this will work.
  2. Snarf makes minimal changes to your traffic.  So, when you do a TREE_CONNECT, it will pass the destination hostname unchanged.  If you make it "localhost", then the server will give you an error about a duplicate name.  This is because servers don't like being called "localhost".  Instead, connect to "127.0.0.1" -- Windows doesn't mind this.  In other words, run "smbclient -U b%b //127.0.0.1/c$", and don't use the name "localhost" in the command.
  3. Windows does weird and unpredictable things.  Sometimes, you may end up with a session that doesn't work.  This could be a bug (so feel free to let us know about it), but it could also just be a vagary of SMB.  Servers don't always keep sessions around as reliably as we want, etc.  So, while Snarf will dramatically improve your ability to get value out of a middled connection, remember that there is still a probabilistic aspect to any MITM attack.
  4. Make sure you follow the on-screen instructions for completing the iptables setup -- we don't apply the last iptables rule in the code because MITM is inherently dangerous.  Think carefully about how that rule should be used.  You probably don't want hundreds of systems coming through, so you can adjust the parameters on the "iptables -t nat -I PREROUTING -p tcp --dport 445 -j SNARF" command to ensure that only the desired systems get snarfed.
