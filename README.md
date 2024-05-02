# ByteCrypt

a simple password manager built in Rust.

**Note**: This program is not meant to be secure. Please do not use it for critical real-world situations.

## Features

- Uses RSA encryption.
- Uses the B-tree data structure for storing data.

## Commands

- `new`: Inserts a new key-value pair.
- `rm`: Removes an existing key-value pair.
- `ls`: Lists all key-value pairs.
- `get`: Gets the value associated with the key.
- `modk`: Modifies the key of a key-value pair.
- `modv`: Modifies the value of a key-value pair.
- `q`: Quits the program safely, saving all updates.
- `help`: Lists all available commands.
- `clear`: Clears the screen.

With a little bit of trial and error, you can easily make it a global program by moving the executable to `/usr/local/bin` and changing the temporary folder location to avoid any collisions.

## Usage
```
$ bytecrypt
```

## Installation
```
$ cago build --release
$ sudo mv /path/to/your/executable /usr/local/bin
```

## Contributions

Contributions to ByteCrypt are welcome! If you have any suggestions or improvements, feel free to open an issue or a pull request.

## License

This project is licensed under the MIT License.

```
$ bytecrypt --version
ByteCrypt 1.0.0
```

(fully tested on ubuntu 23.10)
