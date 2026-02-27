std::process::Command::new("cargo")
    .arg("run")
    .arg("...")
    .output()
    .expect("failed to execute process");

let mut command = std::process::Command::new("cargo");
command.arg("run").arg("...");