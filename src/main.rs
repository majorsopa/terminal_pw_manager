use clap::{Parser, Subcommand};
use obfstr::{obfstmt, obfstr};
use std::fs::{OpenOptions, create_dir, File};
use std::fs;
use std::io::Write;
use std::path::Path;
use serde::{Serialize, Deserialize};
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use std::time::{SystemTime, UNIX_EPOCH};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use aes_gcm_siv::aead::{Aead, NewAead};




fn get_password(buf: &mut [u8]) -> &str {
  // hardcode this string as your password
  obfstr!(buf <- "password!")
}

fn get_key(buf: &mut [u8]) -> &str {
  // hardcode this string as your encryption key.
  // ensure it is the same length (32 characters)
  obfstr!(buf <- "keykeykeykeykeykeykeykeykeykeyke")
}




#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
  /// Login password
  #[clap(short, long)]
  password: String,
  
  /// Subcommand to execute
  #[clap(subcommand)]
  sub_cmd: SubCmd,
}

/// Subcommands
#[derive(Subcommand, Debug)]
enum SubCmd {
  /// Set up the config files
  Initiate,

  /// login to the manager
  AddPassword {
    /// What this password is for
    #[clap(short, long)]
    identifier: String,
    
    /// Username
    #[clap(short, long)]
    username: String,
    
    /// Password
    #[clap(short, long)]
    password: String,
  },

  /// Generate a new password based on your config
  GenPassword,

  /// Change your config
  ChangeConfig {
    /// Minimum length for a new password
    #[clap(long)]
    minimum: u32,

    /// Maximum length for a new password
    #[clap(long)]
    maximum: u32,
  }
}


fn main() {
  let args = Args::parse();
  
  {
    let mut buf = [0u8; 64];
    obfstmt! {
      if args.password != get_password(&mut buf) {
        panic!("wrong password");
      };
    }
  }
  
  match args.sub_cmd {
    SubCmd::Initiate => initiate(),
    SubCmd::AddPassword { identifier, username, password } => add_password(identifier, username, password),
    SubCmd::GenPassword => gen_password(),
    SubCmd::ChangeConfig { minimum, maximum } => {}
  }
}



#[derive(Serialize, Deserialize)]
struct Config {
  new_passwords_config: NewPasswordsConfig,
}

#[derive(Serialize, Deserialize)]
struct NewPasswordsConfig {
  new_password_min_length: u32,
  new_password_max_length: u32,
}


fn initiate() {
  let config_file = OpenOptions::new()
    .write(true)
    .create_new(true)
    .open("config.toml");

  if config_file.is_err() {
    panic!("config already exists");
  }

  let mut config_file = config_file.unwrap();

  config_file.write_all(toml::to_string(&Config {
    new_passwords_config: NewPasswordsConfig {
      new_password_min_length: 12,
      new_password_max_length: 20
    }
  }).unwrap().as_bytes()).unwrap();


  let passwords_path = Path::new("passwords");
  if !passwords_path.exists() {
    create_dir(passwords_path).unwrap();
  }


  println!("initiated");
}

fn add_password(identifier: String, username: String, new_password: String) {

  let mut buf = [0u8; 64];
  let key = Key::from_slice(get_key(&mut buf).as_bytes());
  let cipher = Aes256GcmSiv::new(key);
  
  let mut nonce_string = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis().to_string();
  while nonce_string.len() > 12 {
    nonce_string.pop();
  }
  let nonce = Nonce::from_slice(
    nonce_string.as_bytes()
  );

  let ciphertext = cipher.encrypt(nonce, new_password.as_bytes().as_ref()).unwrap();


  let identifier_path = {
    let mut path = "passwords/".to_string();
    path.push_str(&*identifier);
    path
  };

  let nonce_path = {
    let mut identifier_path = identifier_path.clone();
    identifier_path.push_str("/.nonce");
    identifier_path
  };

  let password_path = {
    let mut identifier_path = identifier_path.clone();
    identifier_path.push_str("/.password");
    identifier_path
  };
  
  create_dir(identifier_path).expect("this identifier already exists");
  let mut nonce_file = File::create(nonce_path).unwrap();
  let mut password_path = File::create(password_path).unwrap();

  
  nonce_file.write_all(nonce_string.as_bytes()).unwrap();
  


  println!("password added");
}

fn gen_password() {
  let config: Config = toml::from_str(
    &fs::read_to_string("config.toml").expect("config does not exist")
  ).expect("config is invalid");
  
  let mut rand_string: String = thread_rng()
    .sample_iter(&Alphanumeric)
    .take(config.new_passwords_config.new_password_max_length.try_into().unwrap())
    .map(char::from)
    .collect();

  let length = thread_rng().gen_range(
    config.new_passwords_config.new_password_min_length..=config.new_passwords_config.new_password_max_length
  );

  while rand_string.len() > length.try_into().unwrap() {
    rand_string.pop();
  }
  
  println!("{}", rand_string);
}
