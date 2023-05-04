use clap::Parser;

/// A simple BrainFuck intepreter and JIT runtime.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    pub file: String,

    /// Number of times to greet
    #[arg(short, long, default_value_t = String::from("intepret"))]
    pub mode: String,
}
