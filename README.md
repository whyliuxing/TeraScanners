# TeraScanners

Uses signature-based memory scanning and DLL injection to dump:
* opcodes (`opcodes.txt`)
* system message IDs (`sysmsgs.txt`)
* datacenter encryption key and IV (`encryption.txt`)

Based on work from luxtau and Gothos from a [RaGEZONE thread](http://forum.ragezone.com/f797/datacenter-parser-1084690/).

## Compiling

Build the TeraScanners project (32-bit only). It'll build the OpcodeDll project as a dependency.

Alternatively, you can get the binaries from the [releases page on GitHub](https://github.com/meishuu/TeraScanners/releases). You will probably need to install the [VC++ 2013 Redistributable](https://www.microsoft.com/en-us/download/details.aspx?id=40784) first.

## Usage

* Open TERA.
* Run `TeraScanners.exe`.
* Wait for the three `.txt` files to be generated.
* You're done.

## Contributing

I have no idea what I'm doing. Please feel free to submit PRs.
