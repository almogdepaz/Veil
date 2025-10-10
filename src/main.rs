use clvm_zk::cli::run_cli;

fn main() {
    if let Err(e) = run_cli() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
