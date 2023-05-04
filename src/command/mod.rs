use clap::Parser;

/// A simple BrainFuck intepreter and JIT runtime.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// The file name of brainfuck program
    #[arg(short, long)]
    pub file: String,

    /// Execute mode: intepret(default) or jit.
    #[arg(short, long, default_value_t = String::from("intepret"))]
    pub mode: String,
}
