Copyright
=====

Duarte Monteiro (etraud123) JSPwn

Nishant Das Patnaik (nishant.dp@) JsPrime

Paul Theriault (pauljt) Scanjs

Introduction
=====

This Application was built in a month under a Summer Internship at Blip.pt (BetFair). A special thanks to AppSec team @ blip.pt and Betfair for all the good feedback and ideas for future implementations.

JSpwn
=====

JavaScript Code Analysis

JSPwn is a modified version of Scanjs + JSPrime.
This tool allow the developers to detect Sinks And Sources of their Applications and find XSS vulnerabilities and DOM XSS (Beta).

With the engine of ScanJS to detect vulnerabilities and the code flux feature of JSprime, this app has the compatibility of detect the vulnerabilities point and backtrack the code.

Video: https://www.youtube.com/watch?v=RWE3852ubH0&

Example
=====

*GUI

[1]$ cd jspwn-master

[2]$ npm install

[3]$ node server.js.

Go to: http://localhost:4000/client/#/scan.

Select File from folder.

Enable REGEXP Custom.

Press "Scan"

*CLI

Usage: $node jspwn.js -t [path/to/app] -j [for json output]


Note: Output is automatic generated

Custom Scanning
======

Source Array: Analyzer.js:26
Sink Array: Analyzer.js:27

Regex: scanctrl.js: 44/45/46

User-Input-Validator: scanctrl.js:865

Attack-vector: scanctrl.js:900


Future Features
======
> Developing a browser extension for JSpwn
