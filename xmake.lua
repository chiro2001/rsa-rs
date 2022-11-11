add_rules("mode.debug", "mode.release")

add_requires("cargo::rsa", {configs = {cargo_toml = path.join(os.scriptdir(), "Cargo.toml")}})

target("rsa")
    set_kind("binary")
    add_files("src/main.rs")
    add_packages("cargo::rsa")
