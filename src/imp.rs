use std::{fs, io};
use std::process::{Command, Stdio};

use include_dir::{include_dir, Dir};

pub struct WindowsActivatorClient {
    program_data: String,
    slmgr: String,
    wow64: String,
    native: String,
}

pub fn pause() -> io::Result<()> {
    Command::new(obfstr!("cmd"))
        .args(&[obfstr!("/c"), obfstr!("pause")])
        .status()
        .map(|_| ())
}

impl WindowsActivatorClient {
    pub fn new() -> Self {
        let windir = std::env::var(obfstr!("windir")).unwrap();
        Self {
            program_data: std::env::var(obfstr!("programdata")).unwrap(),
            slmgr: {
                let mut path = std::env::var(obfstr!("SYSTEMROOT")).unwrap();
                path.push_str(obfstr!("\\System32\\slmgr.vbs"));
                path
            },
            wow64: format!("{}{}", windir, obfstr!("\\SysWOW64")),
            native: format!("{}{}", windir, obfstr!("\\sysnative")),
        }
    }

    pub fn install_pk(&self) -> io::Result<()> {
        let pk = {
            let mut s = String::from_utf8(Command::new(format!("{}{}", self.wow64, obfstr!("\\WindowsPowershell\\v1.0\\powershell.exe")))
                .args(&[
                    obfstr!("-c"),
                    obfstr!("&"),
                    obfstr!("$env:SYSTEMROOT\\sysnative\\WindowsPowershell\\v1.0\\powershell.exe"),
                    obfstr!("-EncodedCommand"),
                    obfstr!("JABBAHMAcwBlAG0AYgBsAHkAQgB1AGkAbABkAGUAcgAgAD0AIABbAEEAcABwAEQAbwBtAGEAaQBuAF0AOgA6AEMAdQByAHIAZQBuAHQARABvAG0AYQBpAG4ALgBEAGUAZgBpAG4AZQBEAHkAbgBhAG0AaQBjAEEAcwBzAGUAbQBiAGwAeQAoADQALAAgADEAKQA7ACAAJABNAG8AZAB1AGwAZQBCAHUAaQBsAGQAZQByACAAPQAgACQAQQBzAHMAZQBtAGIAbAB5AEIAdQBpAGwAZABlAHIALgBEAGUAZgBpAG4AZQBEAHkAbgBhAG0AaQBjAE0AbwBkAHUAbABlACgAMgAsACAAJABGAGEAbABzAGUAKQA7ACAAJABhACAAPQAgACQATQBvAGQAdQBsAGUAQgB1AGkAbABkAGUAcgAuAEQAZQBmAGkAbgBlAFQAeQBwAGUAKAAwACkAOwAgAFsAdgBvAGkAZABdACQAYQAuAEQAZQBmAGkAbgBlAFAASQBuAHYAbwBrAGUATQBlAHQAaABvAGQAKAAnAEcAZQB0AEUAZABpAHQAaQBvAG4ASQBkAEYAcgBvAG0ATgBhAG0AZQAnACwAIAAnAHAAawBlAHkAaABlAGwAcABlAHIALgBkAGwAbAAnACwAIAAnAFAAdQBiAGwAaQBjACwAIABTAHQAYQB0AGkAYwAnACwAIAAxACwAIABbAGkAbgB0AF0ALAAgAEAAKABbAFMAdAByAGkAbgBnAF0ALAAgAFsAaQBuAHQAXQAuAE0AYQBrAGUAQgB5AFIAZQBmAFQAeQBwAGUAKAApACkALAAgADEALAAgADMAKQA7ACAAJABlAGkAZAAgAD0AIAAwADsAIABbAHYAbwBpAGQAXQAkAGEALgBDAHIAZQBhAHQAZQBUAHkAcABlACgAKQA6ADoARwBlAHQARQBkAGkAdABpAG8AbgBJAGQARgByAG8AbQBOAGEAbQBlACgAKABHAGUAdAAtAFcAaQBuAGQAbwB3AHMARQBkAGkAdABpAG8AbgAgAC0ATwBuAGwAaQBuAGUAKQAuAEUAZABpAHQAaQBvAG4ALAAgAFsAcgBlAGYAXQAkAGUAaQBkACkAOwAgACQAYgAgAD0AIAAkAE0AbwBkAHUAbABlAEIAdQBpAGwAZABlAHIALgBEAGUAZgBpAG4AZQBUAHkAcABlACgAMQApADsAIABbAHYAbwBpAGQAXQAkAGIALgBEAGUAZgBpAG4AZQBQAEkAbgB2AG8AawBlAE0AZQB0AGgAbwBkACgAJwBTAGsAdQBHAGUAdABQAHIAbwBkAHUAYwB0AEsAZQB5AEYAbwByAEUAZABpAHQAaQBvAG4AJwAsACAAJwBwAGsAZQB5AGgAZQBsAHAAZQByAC4AZABsAGwAJwAsACAAJwBQAHUAYgBsAGkAYwAsACAAUwB0AGEAdABpAGMAJwAsACAAMQAsACAAWwBpAG4AdABdACwAIABAACgAWwBpAG4AdABdACwAIABbAFMAdAByAGkAbgBnAF0ALAAgAFsAUwB0AHIAaQBuAGcAXQAuAE0AYQBrAGUAQgB5AFIAZQBmAFQAeQBwAGUAKAApACwAIABbAFMAdAByAGkAbgBnAF0ALgBNAGEAawBlAEIAeQBSAGUAZgBUAHkAcABlACgAKQApACwAIAAxACwAIAAzACkAOwAgACQAcABrACAAPQAgACcAJwA7ACAAWwB2AG8AaQBkAF0AJABiAC4AQwByAGUAYQB0AGUAVAB5AHAAZQAoACkAOgA6AFMAawB1AEcAZQB0AFAAcgBvAGQAdQBjAHQASwBlAHkARgBvAHIARQBkAGkAdABpAG8AbgAoACQAZQBpAGQALAAgACIAUgBlAHQAYQBpAGwAIgAsACAAWwByAGUAZgBdACQAcABrACwAIABbAHIAZQBmAF0AJABuAHUAbABsACkAOwAgACQAcABrAA==")
                ])
                .output()?
                .stdout)
                .unwrap();
            s.truncate(s.trim_end().len());
            s
        };

        println!("{} {pk}...", obfstr!("[STATUS] Installing"));
        if !Command::new(obfstr!("cscript.exe"))
            .args(&[obfstr!("//nologo"), &self.slmgr, obfstr!("-ipk"), &pk])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success()
        {
            panic!("{}", obfstr!("Installing product key failed!"));
        }

        Ok(())
    }

    pub fn create_ticket(&self) -> io::Result<()> {
        const UNIVERSAL_TICKETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/Universal_Tickets");
        let pfn_xml = {
            let mut s = String::from_utf8(Command::new(format!("{}{}", self.wow64, obfstr!("\\WindowsPowershell\\v1.0\\powershell.exe")))
                .args(&[
                    obfstr!("-c"),
                    obfstr!("&"),
                    obfstr!("$env:SYSTEMROOT\\sysnative\\WindowsPowershell\\v1.0\\powershell.exe"),
                    obfstr!("-EncodedCommand"),
                    obfstr!("KABHAGUAdAAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAASABLAEwATQA6AFwAUwBZAFMAVABFAE0AXABDAHUAcgByAGUAbgB0AEMAbwBuAHQAcgBvAGwAUwBlAHQAXABDAG8AbgB0AHIAbwBsAFwAUAByAG8AZAB1AGMAdABPAHAAdABpAG8AbgBzACkALgBPAFMAUAByAG8AZAB1AGMAdABQAGYAbgA=")
                ])
                .output()?
                .stdout)
                .unwrap();
            s.truncate(s.trim_end().len());
            s.push_str(obfstr!(".xml"));
            s
        };

        let src = UNIVERSAL_TICKETS.get_file(&pfn_xml).unwrap_or_else(|| {
            _ = Command::new(obfstr!("cscript.exe"))
                .args(&[obfstr!("//nologo"), &self.slmgr, obfstr!("-upk")])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            panic!("{}", obfstr!("Windows Edition not supported!!"));
        });

        println!("{}", obfstr!("[STATUS] Creating ticket..."));
        fs::write(
            format!(
                "{}{}{pfn_xml}",
                self.program_data,
                obfstr!("\\Microsoft\\Windows\\ClipSVC\\GenuineTicket\\")
            ),
            src.contents(),
        )?;
        Ok(())
    }

    pub fn install_ticket(&self) -> io::Result<()> {
        println!("{}", obfstr!("[STATUS] Installing ticket..."));
        if !Command::new(format!("{}\\{}", self.wow64, obfstr!("cmd.exe")))
            .args(&[
                obfstr!("/c"),
                &format!("{}\\{}", self.native, obfstr!("cmd.exe")),
                obfstr!("/c"),
                obfstr!("ClipUp.exe"),
                obfstr!("-v"),
                obfstr!("-o"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success()
        {
            panic!("{}", obfstr!("Migrating licenses via ClipUp failed!"));
        }

        if !Command::new(obfstr!("cscript.exe"))
            .args(&[obfstr!("//nologo"), &self.slmgr, obfstr!("-ato")])
            .status()?
            .success()
        {
            panic!("{}", obfstr!("Activating ticket failed!"));
        }

        if !Command::new(obfstr!("cscript.exe"))
            .args(&[obfstr!("//nologo"), &self.slmgr, obfstr!("-xpr")])
            .status()?
            .success()
        {
            panic!("{}", obfstr!("Displaying activation status failed!"))
        }

        Ok(())
    }
}
