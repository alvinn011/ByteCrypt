´´´
 ____        _        ____                  _   
| __ ) _   _| |_ ___ / ___|_ __ _   _ _ __ | |_ 
|  _ \| | | | __/ _ \ |   | '__| | | | '_ \| __|
| |_) | |_| | ||  __/ |___| |  | |_| | |_) | |_ 
|____/ \__, |\__\___|\____|_|   \__, | .__/ \__|
       |___/                    |___/|_|    
´´´




This is a simple password manager built in rust (tested on ubuntu 23.10).
NOTE: This program is not meant to be safe, please dont use it in critical real world situations.

Features:
uses RSA encryption
uses the b-tree data structure for storing data

commands:
´´´
  +
  | 'new'   inserts a new key-value pair
  | 'rm'    removes an existing key-value pair
  | 'ls'    lists all key-value pairs
  | 'get'   gets the value associated with the key
  | 'modk'  modifies the key of a key-value pair
  | 'modv'  modifies the value of a key-value pair
  | 'q'     quits the program safely, saving all updates
  | 'help'  lists all available commands
  | 'clear' clears the screen
  +

´´´


with a little of trial and error you can easily make it a global program
by moving the executable to /usr/local/bin and changing the tmp folder location
to avoid any collisions
