::

                 )\.-.     .-,.-.,-.   .-./(   .')       .')
               ,' ,-,_)    ).-, ,-.( ,'     ) ( /       ( /
              (  .   __        ))   (  .-, (   ))        ))
               ) '._\ _)  .-._((     ) '._\ )  )'._.-.   )'._.-.
              (  ,   (   (      )   (  ,   (  (       ) (       )
               )/'._.'    '._.\(     )/ ._.'   )/,__.'   )/,__.'


                     ==================================
                     Gjoll is said to be freezing cold,
                     and have knives flowing through it
                     ==================================

=====
GJOLL
=====

 Gjoll is a C library for building secure F2F networks, useful for bypassing NAT
 restrictions and enabling a trusted group of people to communicate online using
 a flexible and secure backend. The Gjoll library uses a central router to relay
 information to and from nodes on the network, and makes development very easy.

Gjoll uses `libuv <https://github.com/joyent/libuv>`_, `ordo <https://github.com/TomCrypto/Ordo>`_, `uthash <https://github.com/troydhanson/uthash>`_ and `lua 5.2 <http://www.lua.org/about.html>`_.

TODO
====

- Automatic reconnect gjoll connections (optional)
- Forwarding
- Automatic node discovering (through friends only)
- F2F encryption (if forwarding, optional)

Documentation
=============

 In coming

To build
========
::
    $ git clone https://github.com/yann2192/Gjoll.git gjoll
    $ cd gjoll
    $ git submodule init && git submodule update
    $ cd lua-5.2.3 && make platform && cd ..
    $ make

|
|  Do "make" and see if your platform is listed.
|  The platforms currently supported are:
|
|  aix ansi bsd freebsd generic linux macosx mingw posix solaris
|
|  If your platform is listed, just do "make xxx", where xxx
|  is your platform name.
|
|  If your platform is not listed, try the closest one or posix, generic,
|  ansi, in this order.

To run the test
===============
::

    $ make test

To launch
=========
::

    $ ./bin/gjoll ./gjollrc.lua

Configuration file
==================

 In coming

