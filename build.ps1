$env:RUSTFLAGS = "-Clink-arg=/DEBUG:NONE -Clink-arg=/Brepro -Ctarget-feature=+crt-static --remap-path-prefix=$home=."
cargo clean
cargo +nightly b -Z build-std=std,panic_abort --target i686-pc-windows-msvc --release
# C:\Users\isaac\Utilities\upx-4.0.2-win64\upx -9 .\target\i686-pc-windows-msvc\release\photon.exe
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x86\mt.exe" -manifest "photon.exe.manifest" -outputresource:".\target\i686-pc-windows-msvc\release\photon.exe";#1
Set-AuthenticodeSignature .\target\i686-pc-windows-msvc\release\photon.exe -Certificate (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)
copy .\target\i686-pc-windows-msvc\release\photon.exe .