use std::collections::btree_map::BTreeMap;
use std::env;
use std::fs::{self, File};
use rand::rngs::OsRng;
use rsa::pkcs8::der::zeroize::Zeroize;
use serde::{Serialize,Deserialize};

use std::io::{self, ErrorKind, Read, Write};
use std::process::{self, Command};
use bincode;
use rsa::{RsaPublicKey,RsaPrivateKey,Pkcs1v15Encrypt};
use rand::{rngs::StdRng, SeedableRng};
use rpassword;
use sha2::{Digest,Sha256};
use termion::color::{Blue, Fg, Green, LightBlue, LightGreen, LightRed, Red, Reset, Yellow};
use whoami;


// THIS CODE IS NOT MEANT TO BE SAFE


fn main() {
    let args:Vec<String> = env::args().collect();
    if args.len() >= 2 {
        match args[1].as_str() {
            "--version" => println!("ByteCrypt v1.0.0"),
            _ => println!("Error: Invalid args!"),
        }
        process::exit(0)
    }
    println!();
    println!("{}{}{}",Fg(LightRed),LOGO,Fg(Reset));
    println!();
    match File::open(std::env::temp_dir().join("bytecrypt/pass.key")) {
        Ok(_)  => auth(std::env::temp_dir().join("bytecrypt/pass.key").to_str().unwrap()),
        Err(err) => {
            match err.kind() {
                ErrorKind::NotFound  => {
                    setup()
                }
                _ => {
                    println!("\n[X] cant start because of error: '{}'\n",err);
                    process::exit(-1)
                }
            }
        }
    }
}
fn auth(path: &str) {
    let out = read_file(path);
    let mut _inp = String::new();
    loop {
        print!("\n[{}+{}] Enter your master password : ",Fg(Yellow),Fg(Reset));
        io::stdout().flush().unwrap();
        let x = rpassword::read_password();
        if let Err(err) = x {
            println!("[{}X{}] Cant read input becuase of error: '{}'",Fg(Red),Fg(Reset),err.to_string());
            continue;
        }
        _inp = x.unwrap().trim().to_owned();
        if hash(&_inp) == out {
            break;
        }else {
            println!("[{}X{}] Password is wrong!",Fg(Red),Fg(Reset));
        }
    }
    let pass = pad_string(_inp);
    inner(pass)
}
fn inner(mut pass:[u8;32]) {
    println!("\n[{}i{}] Generating RSA keypair . . .",Fg(LightBlue),Fg(Reset));
    let mut rand: StdRng = SeedableRng::from_seed(pass);
    let (privkey,pubkey) = gen_keypair(&mut rand);
    println!("\n[{}i{}] Loading/creating DB . . .",Fg(LightBlue),Fg(Reset));
    let mut db;
    if let Ok(metadata) = fs::metadata(std::env::temp_dir().join("bytecrypt/main.bin")) {
        if metadata.len() == 0 {
            db = DB::new()
        }   
        else {
            let temp = DB::load(privkey);
            if let Err(err) = temp {
                println!("[{}X{}] Cant load db because of error: '{}'",Fg(Red),Fg(Reset),err.to_string());
                process::exit(-1);
            }
            db = temp.unwrap();
        }
    }else {
        println!("[{}X{}] '{}' does not exist! ",Fg(Red),Fg(Reset),std::env::temp_dir().join("bytecrypt/main.bin").to_str().unwrap());
        println!("        remove the 'temp' folder to redo setup");
        process::exit(-1);
    }
    let username = whoami::username();
    println!();
    println!("  Welcome {}, to ByteCrypt!",username);
    println!("  feel free to type in commands! ('q' to quit, 'help' to get the list of commands)");
    println!();
    let mut _userin;
    loop {
        _userin = String::new();
        print!("{}{}{}{}: ByteCrypt{}$ ",Fg(LightGreen),username,Fg(Reset),Fg(Blue),Fg(Reset));
        io::stdout().flush().unwrap();
        let x = io::stdin().read_line(&mut _userin);
        if let Err(err) = x {
            println!("[{}X{}] Cant read input becuase of error: '{}'",Fg(Red),Fg(Reset),err.to_string());
            continue;
        }
        _userin = _userin.trim().to_owned();
        match _userin.as_str() {
            "help" => {
                println!();
                println!("  +");
                println!("  | 'new'   inserts a new key-value pair");
                println!("  | 'rm'    removes an existing key-value pair");
                println!("  | 'ls'    lists all key-value pairs");
                println!("  | 'get'   gets the value associated with the key");
                println!("  | 'modk'  modifies the key of a key-value pair");
                println!("  | 'modv'  modifies the value of a key-value pair");
                println!("  | 'q'     quits the program safely, saving all updates");
                println!("  | 'help'  lists all available commands");
                println!("  | 'clear' clears the screen");
                println!("  +");
                println!();
                continue;
            }
            "new" => {
                let mut ident = String::new();
                let mut user = String::new();
                let mut passw = String::new();
                print!("\n[{}+{}] Insert identifier: ",Fg(Yellow),Fg(Reset));
                io::stdout().flush().unwrap();

                let x = io::stdin().read_line(&mut ident);
                if let Err(err) = x {
                    println!("[{}X{}] Cant read input becuase of error: '{}'",Fg(Red),Fg(Reset),err.to_string());
                    continue;
                }
                ident = ident.trim().to_owned();

                print!("\n[{}+{}] Insert username: ",Fg(Yellow),Fg(Reset));
                io::stdout().flush().unwrap();

                let x = io::stdin().read_line(&mut user);
                if let Err(err) = x {
                    println!("[{}X{}] Cant read input becuase of error: '{}'",Fg(Red),Fg(Reset),err.to_string());
                    continue;
                }
                user = user.trim().to_owned();

                print!("\n[{}+{}] Insert password: ",Fg(Yellow),Fg(Reset));
                io::stdout().flush().unwrap();

                let x = io::stdin().read_line(&mut passw);
                if let Err(err) = x {
                    println!("[{}X{}] Cant read input becuase of error: '{}'",Fg(Red),Fg(Reset),err.to_string());
                    continue;
                }
                passw = passw.trim().to_owned();
                if let Some(_) = db.get(&ident) {
                    for i in 1..usize::MAX {
                        let f = format!("{}{}",ident,i);
                        if let Some(_) = db.get(&f) {
                        }else {
                            ident = f;
                            break;
                        }
                    };
                    println!("\n[{}i{}] Identifier already exist, changed new to : '{}'",Fg(LightBlue),Fg(Reset),ident);
                }
                db.insert(&ident, &user, &passw);
                passw.zeroize();
                println!();
                continue;
            }
            "rm" => {
                let mut ident = String::new();
                print!("\n[{}+{}] Insert identifier: ",Fg(Yellow),Fg(Reset));
                io::stdout().flush().unwrap();

                let x = io::stdin().read_line(&mut ident);
                if let Err(err) = x {
                    println!("[{}X{}] Cant read input becuase of error: '{}'",Fg(Red),Fg(Reset),err.to_string());
                    continue;
                }
                ident = ident.trim().to_owned();
                db.remove(&ident);
                println!();
                continue;
            }
            "ls" => {
                println!();
                let k = db.list();
                for thing in k {
                    println!("id: '{}' -> user: '{}', passw: '{}'",thing.0,thing.1.user,thing.1.passw)
                }
                println!();
                continue;
            }
            "q" => {
                println!("\n[{}i{}] Saving all updates . . .",Fg(LightBlue),Fg(Reset));
                let v = db.enc_for_save(pubkey.to_owned());
                if let Err(err) = v {
                    println!("[{}X{}] Error while saving: {}\n",Fg(Red),Fg(Reset),err);
                    continue;
                }
                write_file(std::env::temp_dir().join("bytecrypt/main.bin").to_str().unwrap(), &v.unwrap());
                println!("\nGoodbye!\n");
                break;
            }
            "get" => {
                let mut ident = String::new();
                print!("\n[{}+{}] Insert identifier: ",Fg(Yellow),Fg(Reset));
                io::stdout().flush().unwrap();

                let x = io::stdin().read_line(&mut ident);
                if let Err(err) = x {
                    println!("[{}X{}] Cant read input becuase of error: '{}'",Fg(Red),Fg(Reset),err.to_string());
                    continue;
                }
                ident = ident.trim().to_owned();
                let thing = db.get(&ident);
                if thing.is_none() {
                    println!("[{}X{}] Key-value pair doesnt exist!\n",Fg(Red),Fg(Reset));
                    continue;
                }else {
                    println!("id: '{}' -> user: '{}', passw: '{}'",ident,thing.unwrap().user,thing.unwrap().passw)
                }
                println!();
                continue;
            }
            "modk" => {
                let mut oldident = String::new();
                print!("\n[{}+{}] Insert old identifier: ",Fg(Yellow),Fg(Reset));
                io::stdout().flush().unwrap();

                let x = io::stdin().read_line(&mut oldident);
                if let Err(err) = x {
                    println!("[{}X{}] Cant read input becuase of error: '{}'",Fg(Red),Fg(Reset),err.to_string());
                    continue;
                }
                oldident = oldident.trim().to_owned();
                let mut newident = String::new();
                print!("\n[{}+{}] Insert identifier: ",Fg(Yellow),Fg(Reset));
                io::stdout().flush().unwrap();

                let x = io::stdin().read_line(&mut newident);
                if let Err(err) = x {
                    println!("[{}X{}] Cant read input becuase of error: '{}'",Fg(Red),Fg(Reset),err.to_string());
                    continue;
                }
                newident = newident.trim().to_owned();
                let x = db.modify_name(&oldident, &newident);
                if let Err(err) = x {
                    println!("[{}X{}] Error while modifying: '{}'\n",Fg(Red),Fg(Reset),err.to_string());
                    continue;
                }
                println!();
                continue;
            }
            "modv" => {
                let mut ident = String::new();
                let mut user = String::new();
                let mut passw = String::new();
                print!("\n[{}+{}] Insert identifier: ",Fg(Yellow),Fg(Reset));
                io::stdout().flush().unwrap();

                let x = io::stdin().read_line(&mut ident);
                if let Err(err) = x {
                    println!("[{}X{}] Cant read input becuase of error: '{}'",Fg(Red),Fg(Reset),err.to_string());
                    continue;
                }
                ident = ident.trim().to_owned();

                print!("\n[{}+{}] Insert username: ",Fg(Yellow),Fg(Reset));
                io::stdout().flush().unwrap();

                let x = io::stdin().read_line(&mut user);
                if let Err(err) = x {
                    println!("[{}X{}] Cant read input becuase of error: '{}'",Fg(Red),Fg(Reset),err.to_string());
                    continue;
                }
                user = user.trim().to_owned();

                print!("\n[{}+{}] Insert password: ",Fg(Yellow),Fg(Reset));
                io::stdout().flush().unwrap();

                let x = io::stdin().read_line(&mut passw);
                if let Err(err) = x {
                    println!("[{}X{}] Cant read input becuase of error: '{}'",Fg(Red),Fg(Reset),err.to_string());
                    continue;
                }
                passw = passw.trim().to_owned();
                let x = db.modify_inner(&ident, &user, &passw);
                if let Err(err) = x {
                    println!("[{}X{}] Error while modifying: '{}'\n",Fg(Red),Fg(Reset),err.to_string());
                    continue;
                }
                passw.zeroize();
                println!();
                continue;
            }
            "clear" => {
                clear_screen();
                continue;
            }
            "" => {}
            _ => {
                println!("[{}X{}] Invalid Command\n",Fg(Red),Fg(Reset));
                continue;
            }
        }
    }
    pass.zeroize()
}
fn setup() {
    let mut _first ;
    let mut _second;
    println!("[{}i{}] Starting setup . . .",Fg(LightBlue),Fg(Reset));
    loop {
        _first = String::new();
        _second = String::new();
        print!("\n[{}+{}] Choose a master password [32 >= len >= 8] : ",Fg(Yellow),Fg(Reset));
        io::stdout().flush().unwrap();
        let x = rpassword::read_password();
        if let Err(err) = x {
            println!("[{}X{}] Cant read input becuase of error: '{}'",Fg(Red),Fg(Reset),err.to_string());
            continue;
        }
        _first = x.unwrap().trim().to_owned();
        print!("[{}+{}] Confirm the master password               : ",Fg(Yellow),Fg(Reset));
        io::stdout().flush().unwrap();
        let x = rpassword::read_password();
        if let Err(err) = x {
            println!("[{}X{}] Cant read input becuase of error: '{}'",Fg(Red),Fg(Reset),err.to_string());
            continue;
        }
        _second = x.unwrap().trim().to_owned();
        if _first != _second {
            println!("[{}X{}] Passwords do not match!",Fg(Red),Fg(Reset));
            continue;
        }
        if _first.len() > 32 {
            println!("[{}X{}] Password is too long!",Fg(Red),Fg(Reset));
            continue;
        }
        if _first.len() < 8 {
            println!("[{}X{}] Password is too short!",Fg(Red),Fg(Reset));
            continue;
        }
        break;
    }
    let pass = pad_string(_first.to_owned());
    let hash = hash(&_first);
    println!("\n[{}i{}] Creating temp directory . . .",Fg(LightBlue),Fg(Reset));
    let temp_dir = std::env::temp_dir().join("bytecrypt");
    create_tempdir(temp_dir.to_str().unwrap().to_string());
    write_file(temp_dir.join("pass.key").to_str().unwrap(), &hash);
    inner(pass);
    _first.zeroize();
    _second.zeroize();
}
fn write_file(path: &str,content: &[u8]) {
    let x = File::create(path.to_owned());
    if let Err(err) = x {
        println!("[{}X{}] Cant open '{}' because of error: '{}'",Fg(Red),Fg(Reset),path,err.to_string());
        process::exit(-1);
    }
    let mut file = x.unwrap();
    let x = file.write(content);
    if let Err(err) = x {
        println!("[{}X{}] Cant write to '{}' because of error: '{}'",Fg(Red),Fg(Reset),path,err.to_string());
        process::exit(-1);
    }
}
fn read_file(path: &str) -> Vec<u8> {
    let x = File::open(path.to_owned());
    if let Err(err) = x {
        println!("[{}X{}] Cant open '{}' because of error: '{}'",Fg(Red),Fg(Reset),path,err.to_string());
        process::exit(-1);
    }
    let mut file = x.unwrap();
    let mut buf = Vec::new();
    let x = file.read_to_end(&mut buf);
    if let Err(err) = x {
        println!("[{}X{}] Cant read '{}' because of error: '{}'",Fg(Red),Fg(Reset),path,err.to_string());
        process::exit(-1);
    }
    buf
}
fn create_tempdir(path: String) {
    create_dir(&path);

    create_file(&(path.to_owned() + "/pass.key"));

    create_file(&(path + "/main.bin"));
    println!("[{}V{}] Created temp directory",Fg(Green),Fg(Reset))
}

fn create_dir(path: &str) {
    let x = fs::create_dir(path.to_owned());
    if let Err(err) = x {
        println!("[{}X{}] Cant create '{}' directory because of error: '{}'",Fg(Red),Fg(Reset),path,err.to_string());
        process::exit(-1);
    }
}
fn create_file(path: &str) {
    let x = File::create_new(path.to_owned());
    if let Err(err) = x {
        println!("[{}X{}] Cant create '{}' because of error: '{}'",Fg(Red),Fg(Reset),path,err.to_string());
        process::exit(-1);
    }
}
fn gen_keypair(rand: &mut StdRng) -> (RsaPrivateKey,RsaPublicKey) {
    let privkeyy = RsaPrivateKey::new(rand, 2048);
    if let Err(err) = privkeyy {
        println!("[{}X{}] Cant gen RSA key pair because of error: '{}'",Fg(Red),Fg(Reset),err.to_string());
        process::exit(-1);
    }
    let privkey = privkeyy.unwrap();
    let pubkey = RsaPublicKey::from(&privkey);
    println!("[{}V{}] Created RSA key pair",Fg(Green),Fg(Reset));
    (privkey,pubkey)
}
fn pad_string(str: String) -> [u8;32] {
    let chars: Vec<char> = str.chars().collect();
    let mut res = [0;32];
    for i in 0..res.len() {
        let ch = chars.get(i);
        if ch.is_none() {
            continue;
        }
        res[i] = ch.unwrap().to_owned() as u8
    }

    res
}
fn hash(str: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(str);
    hasher.finalize().to_vec()
}

#[derive(Clone)]
struct DB {
    store : BTreeMap<String, Pair>
}
#[derive(Clone,Serialize,Deserialize)]
struct Pair {
    user : String,
    passw: String,
}
impl DB {
    fn new() -> Self {
        Self { store: BTreeMap::new() }
    }
    fn list(&self) -> Vec<(String,Pair)> {
        let mut res = Vec::new();
        for key in self.store.to_owned() {
            res.push(key)
        }
        res
    }
    fn insert(&mut self,ident: &str,user: &str,passw: &str) {
        self.store.insert(ident.to_owned(), Pair { user: user.to_owned(), passw: passw.to_owned() });
    }
    fn remove(&mut self,ident: &str) -> Option<Pair> {
        self.store.remove(ident)
    }
    fn modify_inner(&mut self,ident: &str,user: &str,passw: &str) -> Result<(), String>{
        if let Some(keyp) = self.store.get_mut(ident) {
            *keyp = Pair {user: user.to_owned(),passw: passw.to_owned()};
            Ok(())
        }else {
            return Err("key-value pair does not exist!".to_owned());
        }
    }
    fn modify_name(&mut self,ident: &str,newident: &str) -> Result<(), String> {
        if let Some(keyp) = self.store.get(ident) {
            self.store.insert(newident.to_owned(), keyp.to_owned());
        }else {
            return Err("key-value pair does not exist!".to_owned());
        }
        self.store.remove(ident);
        Ok(())
    }
    fn get(&self, ident: &str) -> Option<&Pair>{
        self.store.get(ident)
    }
    fn enc_for_save(&self,pubkey: RsaPublicKey) -> Result<Vec<u8>,String> {
        let mid = bincode::serialize(&self.store.to_owned());
        if let Err(err) = mid {
            return Err(format!("Cant serialize your passwors, all updates will be lost! error: '{}'",err.to_string()));
        }
        let res = pubkey.encrypt(&mut OsRng, Pkcs1v15Encrypt, &mid.unwrap());
        if let Err(err) = res {
            return Err(format!("Cant encrypt your passwors all updates will be lost! error: '{}'",err.to_string()));
        }
        Ok(res.unwrap())
    }
    fn load(privkey: RsaPrivateKey) -> Result<Self,String>{
        let out = read_file(std::env::temp_dir().join("bytecrypt/main.bin").to_str().unwrap());
        let mid = privkey.decrypt(Pkcs1v15Encrypt,&out);
        if let Err(err) = mid {
            return Err(format!("Cant decrypt file because of error: '{}'",err.to_string()));
        }
        let res: Result<BTreeMap<String,Pair>, Box<bincode::ErrorKind>> = bincode::deserialize(&mid.unwrap());
        if let Err(err) = res {
            return Err(format!("Cant deserialize file because of error: '{}'",err.to_string()));
        }
        Ok(Self { store: res.unwrap() })
    }
}

const LOGO: &'static str = r#"
 ____        _        ____                  _   
| __ ) _   _| |_ ___ / ___|_ __ _   _ _ __ | |_ 
|  _ \| | | | __/ _ \ |   | '__| | | | '_ \| __|
| |_) | |_| | ||  __/ |___| |  | |_| | |_) | |_ 
|____/ \__, |\__\___|\____|_|   \__, | .__/ \__|
       |___/                    |___/|_|        
"#;

fn clear_screen() {
    #[cfg(target_os = "windows")]
    let _ = Command::new("cmd").arg("/c").arg("cls").status();

    #[cfg(not(target_os = "windows"))]
    let _ = Command::new("clear").status();
}
