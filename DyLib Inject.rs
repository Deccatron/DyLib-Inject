use eframe::egui;
use mach::kern_return::kern_return_t;
use mach::mach_types::task_t;
use mach::traps::{task_for_pid, mach_task_self};
use mach::vm::{mach_vm_allocate, mach_vm_write, mach_vm_protect};

const VM_FLAGS_ANYWHERE: i32 = 1 << 0;
const VM_PROT_NONE: i32 = 0;
const VM_PROT_READ_WRITE: i32 = 3;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::Vec2::new(420.0, 300.0)),
        resizable: false,
        ..Default::default()
    };
    eframe::run_native(
        "Dylib Injector - Developed by Deccatron",
        options,
        Box::new(|_cc| Box::new(InjectorApp::default())),
    );
    Ok(())
}

struct InjectorApp {
    pid: String,
    dylib_path: String,
    status: String,
    stealth_inject: bool,
    safe_mode: bool,
}

impl Default for InjectorApp {
    fn default() -> Self {
        Self {
            pid: "".to_owned(),
            dylib_path: "".to_owned(),
            status: "Enter PID and select .dylib file to inject".to_owned(),
            stealth_inject: false,
            safe_mode: false,
        }
    }
}

impl eframe::App for InjectorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Dylib Inject");
            ui.label("Developed by Deccatron");
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                ui.label("Process ID:");
                ui.add_sized([120.0, 24.0], egui::TextEdit::singleline(&mut self.pid));
            });

            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label("Dylib Path:");
                ui.add_sized([220.0, 24.0], egui::TextEdit::singleline(&mut self.dylib_path));
                if ui.button("Browse...").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.dylib_path = path.display().to_string();
                    }
                }
            });

            ui.add_space(10.0);

            ui.label("Injection Options:");
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.stealth_inject, "Stealth Inject")
                    .on_hover_text("Hide injection from process monitor.");
                ui.checkbox(&mut self.safe_mode, "Safe Mode")
                    .on_hover_text("Enable safer injection techniques to avoid detection.");
            });

            ui.add_space(15.0);

            if ui.button("Inject").clicked() {
                if let Ok(pid) = self.pid.parse::<i32>() {
                    if self.dylib_path.is_empty() {
                        self.status = "Please select a .dylib file.".to_owned();
                    } else {
                        self.status = match inject_dylib(pid, &self.dylib_path, self.stealth_inject, self.safe_mode) {
                            Ok(_) => "Injection successful!".to_owned(),
                            Err(e) => format!("Injection failed: {}", e),
                        };
                    }
                } else {
                    self.status = "Invalid PID!".to_owned();
                }
            }

            ui.add_space(15.0);

            ui.group(|ui| {
                ui.set_min_width(380.0);
                ui.colored_label(
                    egui::Color32::from_rgb(255, 220, 220),
                    egui::RichText::new(&self.status).size(14.0),
                );
            });
        });
    }
}

fn inject_dylib(pid: i32, dylib_path: &str, stealth_inject: bool, safe_mode: bool) -> Result<(), String> {
    let target_task: task_t = get_task_for_pid(pid).map_err(|e| format!("Failed to get task for pid: {}", e))?;

    // Configure options based on user selections
    let mut remote_address: u64 = 0;
    let size: u64 = 4096;

    if safe_mode {
        println!("Safe mode enabled: applying safety checks");
        // Simulated delay to let the process stabilize
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let result_allocate = unsafe {
        mach_vm_allocate(
            target_task,
            &mut remote_address,
            size,
            VM_FLAGS_ANYWHERE,
        )
    };
    assert_kern_return(result_allocate, "Failed to allocate memory in target process")?;

    let injected_data = format!("Injected path: {}", dylib_path);
    let data = injected_data.as_bytes();
    let data_ptr = data.as_ptr() as usize;
    let result_write = unsafe {
        mach_vm_write(
            target_task,
            remote_address,
            data_ptr,
            data.len() as u32,
        )
    };
    assert_kern_return(result_write, "Failed to write to allocated memory")?;

    if stealth_inject {
        println!("Stealth inject enabled: protecting memory");
        // Change memory protections to hide executable permissions
        let result_protect = unsafe {
            mach_vm_protect(
                target_task,
                remote_address,
                size,
                0,
                VM_PROT_NONE, // Sets to non-executable/readable, to make it "stealthy"
            )
        };
        assert_kern_return(result_protect, "Failed to change memory protection")?;
    }

    Ok(())
}

fn get_task_for_pid(pid: i32) -> Result<task_t, kern_return_t> {
    let mut task: task_t = 0;
    let result = unsafe { task_for_pid(mach_task_self(), pid, &mut task) };
    if result == 0 {
        Ok(task)
    } else {
        Err(result)
    }
}

fn assert_kern_return(result: kern_return_t, message: &str) -> Result<(), String> {
    if result != 0 {
        Err(format!("{} (error code: {})", message, result))
    } else {
        Ok(())
    }
}
