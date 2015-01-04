cuber
=====

This is a tool that signs recovery and boot images for Little Kernel bootloaders affected by [CVE-2014-0973](https://www.codeaurora.org/projects/security-advisories/incomplete-signature-parsing-during-boot-image-authentication-leads-to-signature-forgery-cve-2014-0973).

vulnerability
--
cuber has been tested working for 3rd-generation Kindle Fire HDX tablets with firmware versions older than 14/13.3.2.4. 
Most likely affects many other devices using Little Kernel bootloaders built prior to June 13, 2014.

requirements
---
* gcc
* libmpc-dev
* libmpfr-dev
* libgmp3-dev
* libssl-dev
* python
* python-dev
* python-pip

...and python package `gmpy2` which can be installed with pip:
```
$ pip install gmpy2
```

installation
---
After ensuring you have all the above packages installed, download the source and compile.
```bash
$ wget https://github.com/Verteo/Cuber/archive/master.zip
$ unzip master.zip
$ cd Cuber-master
$ make
```

usage
---
```
cuber --check /path/to/file.img
```
Checks if image would pass signature verification.<br>
*You may also use `-c` in place of `--check`.*


```
cuber --sign /path/to/input/file.img /path/to/output/file.img
```
Creates a signature and outputs a signed image.<br>
*You may also use `-s` in place of `--sign`.*