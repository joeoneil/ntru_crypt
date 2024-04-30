#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

use std::{fmt::Display, fs, io::{self, Read, Write}, process::exit};

use base64::Engine;
use clap::{Parser, Subcommand};
use anyhow::{anyhow, Result};
use ntru_crypt::{keygen, params::{self, NTRUParams}, poly::Polynomial, PrivateKey, PublicKey};

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[arg(long, short, action=clap::ArgAction::SetTrue)]
    debug: bool,
}

#[derive(Subcommand, Clone)]
enum Command {
    #[command(about = "Generate key pairs")]
    Keygen {
        #[arg(
            long, short,
            value_parser = clap::builder::PossibleValuesParser::new(["0", "1", "2", "3"]),
            help = "security level of the generated keys"
            )]
        security: String,
        #[arg(
            long, short,
            default_value_t = String::from("id_ntru"),
            help = "private key will be in [filename], public key will be in [filename].pub"
        )]
        filename: String,
    },
    #[command(about = "Encrypt data with a given public key")]
    Encrypt {
        #[arg(
            long = "input-file", visible_alias = "if",
            help = "input file to encrypt. If not present, reads from stdin"
        )]
        infile: Option<String>,
        #[arg(
            long = "key-file", visible_alias = "kf", 
            help = "public key to encrypt the given data with",
            )]
        keyfile: String,
        #[arg(
            long = "output-format", visible_alias = "of",
            default_value_t = Format::Binary,
            help = "format of the output data. Text is ignored (treated as binary)"
            )]
        out_format: Format,
    },
    #[command(about = "Decrypt data with a given private key")]
    Decrypt {
        #[arg(
            long = "input-file", visible_alias = "if",
            help = "input file to decrypt. If not present, reads from stdin"
        )]
        infile: Option<String>,
        #[arg(
            long = "input-format", visible_alias = "ifmt", 
            default_value_t = Format::Binary, 
            help = "format of the input data. Text is ignored (treated as binary)"
            )]
        in_format: Format,
        #[arg(
            long = "key-file", visible_alias = "kf",
            help = "private key to decrypt the given data with"
            )]
        keyfile: String,
        #[arg(
            long = "output-format", visible_alias = "of",
            default_value_t = Format::Binary, 
            help = "format of the output data"
            )]
        out_format: Format,
    },
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum Format {
    Text,
    Binary,
    Base64,
    Base64Web,
}

impl Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Format::Text => "Text",
                Format::Binary => "Binary",
                Format::Base64 => "Base64",
                Format::Base64Web => "Base64Web",
            }
        )
    }
}

fn main() {
    let cmd = Cli::parse();
    match match cmd.command {
        Command::Keygen { security, filename } => keygen_cmd(security.parse().unwrap_or(0), filename, cmd.debug),
        Command::Encrypt { infile, keyfile, out_format } => encrypt_cmd(infile, keyfile, out_format, cmd.debug),
        Command::Decrypt { infile, in_format, keyfile, out_format } => decrypt_cmd(infile, in_format, keyfile, out_format, cmd.debug),
    } {
        Ok(_) => exit(0),
        Err(e) => {
            eprintln!("{}", e);
            exit(1);
        }
    }
}

fn keygen_cmd(security: u8, filename: String, debug: bool) -> Result<()> {

    fn keygen_inner<const N: usize, const P: i16, const Q: i16>(params: &NTRUParams<N, P, Q>, debug: bool) -> (Vec<u8>, Vec<u8>) 
    where
        [(); N + 1]:,
        [(); N - 1]:,
    {
        let kp = keygen(params);

        if debug {
            eprintln!("h  : {:?}", kp.pubkey.key);
            eprintln!("f  : {:?}", kp.privkey.key_f);
            eprintln!("f_p: {:?}", kp.privkey.key_fp);

            eprint!("pubkey (bytes):  ");
            for b in kp.pubkey.as_bytes() {
                eprint!("{:02x}", b);
            }
            eprintln!("");

            eprint!("privkey (bytes): ");
            for b in kp.privkey.as_bytes() {
                eprint!("{:02x}", b);
            }
            eprintln!("");
        }

        kp.as_bytes()
    }

    let mut keypair = match security {
        0 => keygen_inner(&params::NTRU_EXAMPLE, debug),
        1 => keygen_inner(&params::NTRU_PAPER_MODERATE, debug),
        2 => keygen_inner(&params::NTRU_PAPER_HIGH, debug),
        3 => keygen_inner(&params::NTRU_PAPER_HIGHEST, debug),
        _ => unreachable!()
    };
    /*

    eprint!("public key: ");
    for b in &keypair.0 {
        eprint!("{:02x}", b)
    }
    eprintln!("");

    eprint!("private key: ");
    for b in &keypair.1 {
        eprint!("{:02x}", b)
    }
    eprintln!("");

    */

    // add marker to key indicating level of security
    keypair.0.insert(0, security);
    keypair.0.insert(1, 0);
    keypair.1.insert(0, security);
    keypair.1.insert(1, 1);

    let e = base64::engine::general_purpose::STANDARD;

    let (pubenc, privenc) = (e.encode(keypair.0), e.encode(keypair.1));

    fs::write(format!("{}.pub", filename), pubenc)?;
    fs::write(format!("{}", filename), privenc)?;

    Ok(())
}

fn encrypt_cmd(in_file: Option<String>, key_file: String, out_format: Format, debug: bool) -> Result<()> {
    let data = if let Some(path) = in_file {
        fs::read(path)?
    } else {
        let mut v = vec![];
        io::stdin().read_to_end(&mut v)?;
        v
    };

    fn encrypt_inner<const N: usize, const P: i16, const Q: i16>(data: &[u8], key_bytes: &[u8], params: &NTRUParams<N, P, Q>, debug: bool) -> Vec<u8> 
    where
        [();  N + 1 ]:,
    {
        let pubkey = PublicKey {
            key: Polynomial::encode::<Q>(key_bytes)[0]
        };

        if debug {
            eprint!("raw key   : ");
            for b in key_bytes {
                eprint!("{:02x}", b)
            }
            eprintln!("");

            eprint!("public key: ");
            for b in pubkey.as_bytes() {
                eprint!("{:02x}", b)
            }
            eprintln!("");

            eprintln!("Read {} bytes", data.len());
        }

        let encrypt = pubkey.encrypt(data, params);

        if debug {
            eprintln!("Encrypted to {} bytes", encrypt.len());
        }
         
        encrypt
    }

    let key_data = base64::engine::general_purpose::STANDARD.decode(fs::read(key_file)?)?;
    let sec = key_data[0];
    let key_type = key_data[1];
    let key_bytes = &key_data[2..];

    match key_type {
        0 => {},
        1 => return Err(anyhow!("Given key_file contained a private key")),
        _ => return Err(anyhow!("Given key_file did not contain a valid key")),
    }

    
    let enc_bytes = match sec {
        0 => encrypt_inner(data.as_slice(), key_bytes, &params::NTRU_EXAMPLE, debug),
        1 => encrypt_inner(data.as_slice(), key_bytes, &params::NTRU_PAPER_MODERATE, debug),
        2 => encrypt_inner(data.as_slice(), key_bytes, &params::NTRU_PAPER_HIGH, debug),
        3 => encrypt_inner(data.as_slice(), key_bytes, &params::NTRU_PAPER_HIGHEST, debug),
        _ => return Err(anyhow!("Given key_file did not contain a valid key")),
    };

    let mut out_bytes = (data.len() as u64).to_le_bytes().to_vec();

    out_bytes.extend(enc_bytes);

    let s;
    io::stdout().write_all(match out_format {
        Format::Text | Format::Binary => {
            out_bytes.as_slice()
        }
        Format::Base64 | Format::Base64Web => {
            let e = match out_format {
                Format::Base64 => base64::engine::general_purpose::STANDARD,
                Format::Base64Web => base64::engine::general_purpose::URL_SAFE,
                _ => unreachable!()
            };
            s = e.encode(out_bytes);
            s.as_bytes()
        }
    })?;

    Ok(())
}

fn decrypt_cmd(in_file: Option<String>, in_format: Format, keyfile: String, out_format: Format, debug: bool) -> Result<()> {
    let data = if let Some(path) = in_file {
        fs::read(path)?
    } else {
        let mut v = vec![];
        io::stdin().read_to_end(&mut v)?;
        v
    };

    let data = match in_format {
        Format::Text | Format::Binary => data,
        Format::Base64 | Format::Base64Web => {
            let e = match in_format {
                Format::Base64 => base64::engine::general_purpose::STANDARD,
                Format::Base64Web => base64::engine::general_purpose::URL_SAFE,
                _ => unreachable!()
            };
            
            e.decode(data)?
        }
    };

    fn decrypt_inner<const N: usize, const P: i16, const Q: i16>(data: &[u8], key_bytes: &[u8], _params: &NTRUParams<N, P, Q>, debug: bool) -> Result<Vec<u8>> 
    where
        [(); N + 1]:, 
    {
        let parts = Polynomial::encode::<Q>(key_bytes);
        let privkey: PrivateKey<N, P, Q> = PrivateKey {
            key_f: parts[0].denormalize(Q as u32),
            key_fp: parts[1].denormalize(P as u32),
        };

        if debug {
            eprint!("raw key: ");
            for b in key_bytes {
                eprint!("{:02x}", b);
            }
            eprint!("key_f  :");
            for b in Polynomial::decode::<Q>(vec![privkey.key_f].as_slice()) {
                eprint!("{:02x}", b);
            }
            eprintln!("");
            eprint!("key_fp :");
            for b in Polynomial::decode::<Q>(vec![privkey.key_fp].as_slice()) {
                eprint!("{:02x}", b);
            }
            eprintln!("");

            eprintln!("key_f : {:?}", privkey.key_f);
            eprintln!("key_fp: {:?}", privkey.key_fp);
            eprintln!("prod  : {:?}", privkey.key_f.mul(privkey.key_fp, P as u32));

        }

        let one = Polynomial::new_one();

        if privkey.key_f.mul(privkey.key_fp, P as u32) != one {
            return Err(anyhow!("Failed to reconstruct private key"))
        }

        let decrypt = privkey.decrypt(data);

        if debug {
            eprintln!("Read {} bytes", data.len());
            eprintln!("Decrypted to {} bytes", decrypt.len());
        }

        Ok(decrypt)
    }
    
    let key_data = base64::engine::general_purpose::STANDARD.decode(fs::read(keyfile)?)?;
    let sec = key_data[0];
    let key_type = key_data[1];
    let key_bytes = &key_data[2..];

    match key_type {
        0 => return Err(anyhow!("Given key_file contained a public key")),
        1 => {}
        _ => return Err(anyhow!("Given key_file did not contain a valid key")),
    }

    let data_len = u64::from_le_bytes(data[0..8].try_into()?);

    let data = &data.as_slice()[8..];

    let mut dec_bytes = match sec {
        0 => decrypt_inner(data, key_bytes, &params::NTRU_EXAMPLE, debug),
        1 => decrypt_inner(data, key_bytes, &params::NTRU_PAPER_MODERATE, debug),
        2 => decrypt_inner(data, key_bytes, &params::NTRU_PAPER_HIGH, debug),
        3 => decrypt_inner(data, key_bytes, &params::NTRU_PAPER_HIGHEST, debug),
        _ => return Err(anyhow!("Given key_file did not contain a valid key")),
    }?;

    if debug {
        eprintln!("Expected {} bytes", data_len);
    }

    // truncate or extend the data with zeros. to its given length
    dec_bytes.resize(data_len as usize, 0);

    let s;
    io::stdout().write_all(match out_format {
        Format::Text => {
            s = String::from_utf8(dec_bytes)?.into_bytes();
            s.as_slice()
        },
        Format::Binary => {
            dec_bytes.as_slice()
        }
        Format::Base64 | Format::Base64Web => {
            let e = match out_format {
                Format::Base64 => base64::engine::general_purpose::STANDARD,
                Format::Base64Web => base64::engine::general_purpose::URL_SAFE,
                _ => unreachable!()
            };
            s = e.decode(dec_bytes)?;
            s.as_slice()
        }
    })?;

    Ok(())
}
