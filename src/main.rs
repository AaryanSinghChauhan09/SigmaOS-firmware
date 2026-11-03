use clap::Parser;
use firmware::firmware;

#[derive(Parser)]
struct Cli;

fn main() -> anyhow::Result<()> {
    let config = firmware::Config::default();
    let mut component = firmware::new(config);
    component.initialize()?;
    println!("SigmaOS-firmware ready");
    Ok(())
}
