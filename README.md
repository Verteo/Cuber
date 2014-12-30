Cuber
=====

This is a tool that signs recovery/boot images for Little Kernel bootloaders dated before 13 June 2014.

Requirements on an example Ubuntu system:
---

libmpc-dev
libmpfr-dev
libgmp3-dev
libssl-dev
python
python-pip

and the following python package:
gmpy2
install it using pip:
`sudo pip install gmpy2`

Why python?
---
It is easier to handle bignums in python than in c++.

Installation:
---
Download source, go to the folder and run make.
 
Usage:
---
 
```Cuber -check path/to/image.img```  
checks if the image would pass the signature verification  
  
```Cuber -sign path/to/input/image.img path/to/output/image.img```  
creates a signature for the given image and creates a new signed at the specified location
