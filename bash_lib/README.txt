==============
 Bash Library
==============

I write a lot a BASH scripts [#oldSkool].
I wanted to do some basic CU automation:
	{ wait for a tag; read a page; analyse the contents; read a different page;
	  do some maths; write to a bunch of pages; etc.}

I looked at a few stock-options (such as `expect`) but ultimately the predictive
CLI in the CU interface presented a number of hurdles not easily addressed by them.

To use this lib, simply put `. cu-daemon.sh` at the top of your script.
The library allows you to:
	`Setup` the CU CLI interface as a background "dæmon" 
		...and automatically `Cleanup` when your script exits
	Use basic `Send` and `Listen` commands to interact with that dæmon
	And a bonus `Status` function
		(which just uses `Send` & `Listen` to get the status of the CU).

The directory also contains a couple of examples.
They're not pretty, they're not perfect, they're just demo/test harnesses.
...But serve well enough as examples.

The library itself is hand-written, and well documented.

For the curious
---------------

It tries to address two core issues.
	1. It strips out the sexy UI interface codes
	2. It attaches via file descriptors to prevent the CLI from terminating
	   after every command (caused by the EOF marker send by `cat`, `echo`, etc.)

