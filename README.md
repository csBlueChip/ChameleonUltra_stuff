# ChameleonUltra_stuff
Companion tools for the Chameleon Ultra

This is a dumping ground for my companion tools for the Chameleon Ultra - a nerd toy for playing with NFC tags.
https://github.com/RfidResearchGroup/ChameleonUltra

You can pick one up from Lab401 for about €130, or AliExpress for about €15 (no, that's not a typo!)

# Bash Library
I write a lot a BASH scripts [#oldSkool]. I wanted to do some basic automation: _{wait for a tag; read a page; analyse the contents; read a different page; do some maths; write to a bunch of pages; etc.}_ ...I looked at a few stock-options (such as `expect`) but ultimately the predictive CLI in the CU interface presented a number of hurdles not easily addressed by them.

This library allows you to `Setup` the CU CLI interface as a background "dæmon" (and automatically `Cleanup` when your script exits), gives basic `Send` and `Listen` commands to interact with that dæmon, and a bonus `Status` function (which just uses `Send` & `Listen` to get the status of the CU).

The directory also contains a couple of examples.

# Serial MitM/Proxy 
I want to drive my CU with a microcontroller (ESP32, RP2040, SAM4S, whatever). I was hoping to see nice ASCII commands between the CLI and the CU, but alas, it (prudently) uses a binary interface. 

This is a serial port "proxy" - you run it, and it attaches to the CU ...then, in a second terminal window, you attach the CLI to the proxy ...The proxy can now see all the data in both directions, and spews it out up the screen.

It will work for any serial port comms (`--no-decode`), but generally it will try to (fully) decode every packet it sees.

*** WARNING ***

This Python script is 100% pure "AI slop". After several arguments with Claude, I got something where the output "looks right" ...If you see an error in the decode, you are well within your rights to suspect this decoder - bug reports greatfully appreciated.

That said, and as defamatory as I generally am about LLMs, it has served me well ...well enough to share it with others.

I do not present this as "my work"; I've barely looked at the code (it's not the worst code I've ever seen, but it is certainly NOT how I would have approached the problem had I done it all by hand).

# Issues & Pull Requests
Always happy for either of these.

# Licencing
All my work is presented as "free" (as in free). I've been using the MIT licence for years, if that's a problem for you, just ask and we'll work it out!
