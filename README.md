liboqs-utils
============

liboqs-utils is a Python tool to help create wrappers for algorithms for incorporation into liboqs (https://github.com/open-quantum-safe/liboqs). This utility is part of the the NIST Post-Quantum Cryptography standardization project.

Overview
--------

liboqs-utils attempts to automate most of the wrapper creation process documented here: https://github.com/open-quantum-safe/liboqs/blob/nist-branch/CONTRIBUTING.md

Due to differences in the algorithms implemented, liboqs-util takes the approach of generating and editing as much of the wrapper/makefiles etc as possible. These scripts may fail to work for non-standard algorithm submissions. Generated makefiles may not work, at the minimum, the intent is to provide content for hand editing.      

Requirements & Installation
---------------------------

liboqs-util was developed with Python 3.6.6, other versions were not tried. See requirements.txt for the dependencies used for `pip`. Older versions of these requirements may also work. Use of python virtual environments is recommended.

After downloading and extracting this repo from GitHub:

```
cd $LIBOQS-UTIL-DIR
python3 -m venv [path-to-virtual-env]
. [path-to-virtual-env]/bin/activate
pip install -r requirements.txt
```

Getting Started
---------------

Follow the `Getting started` and `Adding the upstream implementation` sections from: https://github.com/open-quantum-safe/liboqs/blob/nist-branch/CONTRIBUTING.md as liboqs-util doesn't cover this. 

Build the upstream code as liboqs-util needs to examine the src and object files. Try either of:
* Easier: compile but **don't** link all the upstream source files (e.g. `gcc -c`).
* Potentially harder: run `make` and use the algorithm Makefile.

liboqs-util covers the steps in `CONTRIBUTING.md`: 
* Creating the OQS wrapper
* Adding to the build system
* Documentation (~50% automated)

Assuming liboqs is installed at `$LIBOQS_DIR`, and you are generating a KEM wrapper for `fake_algorithm`:

```
cd $LIBOQS_DIR
python3 $LIBOQS-UTIL-DIR/oqs/generate.py fake_algorithm
git status
```

If `generate.py` completes without a stack trace, `git status` will show several new and modified C source, header and Makefiles. Try `make` to see how much of the build process completes. The generated makefile may require manual tweaks in order to build correctly.

Once the build completes cleanly, complete the Testing, Documentation and Submitting sections of as per `CONTRIBUTING.md`. liboqs-util generates a partially filled in algorithm data sheet for ease.     

Caveats
-------

As of September 2018:
 * Scripts are in a beta state & only work generate KEM wrappers.
 * Error handling has been mostly ignored for the beta version.
 * SIGs are not yet handled.
 * Rerunning the script overwrites manual changes in generated Makefiles.
