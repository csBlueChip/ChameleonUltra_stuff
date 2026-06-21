===================
 Serial MitM/Proxy
===================

I want to drive my CU with a microcontroller (ESP32, RP2040, SAM4S, whatever).
I was hoping to see nice ASCII commands between the CLI and the CU,
but alas, it (prudently) uses a binary interface.

This is a serial port "proxy"...

You run it : `python3 cu-mitm.py`
	it attaches to the CU (typically `/dev/ttyACM0`)
	and create a new serial port (typically `/dev/pts/2`)

Then, in a second terminal window, 
	Run the CLI : `python3 ChameleonUltra/software/script/chameleon_cli_main.py`
	and attach to the proxy : `hw connect -p /dev/pts/2`

The proxy can now see all the data in both directions,
	and spews it out up the screen in a more human-readable format.

It will actually work for any serial port comms (`--no-decode`),
but generally it will try to (fully) decode every packet it sees.

*** WARNING ***

This Python script is 100% pure "AI slop". After several arguments with Claude,
I eventually got something where the output "looks right"
If you see an error in the decode, you are well within your rights to 
suspect this decoder ...bug reports greatfully appreciated.

That said, and as defamatory as I generally am about LLMs, it has served me well
...well enough to share it with others.

I do not present this as "my work"; I've barely looked at the code (it's not 
the worst code I've ever seen, but it is certainly NOT how I would have approached 
the problem had I done it all by hand).
