use std::str::FromStr;

use clap::{command, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct CliArguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    TestIssueCredential {
        #[arg(short, long)]
        input: String,
    },
    TestIssuePresentation {
        #[arg(short, long)]
        input: String,
    },
}

fn main() {
    let args = CliArguments::parse();
    match args.command {
        Command::TestIssueCredential { input } => {
            let vc = ssi::credential::VerifiableCredential::from_str(&input).unwrap();
            println!("{}", vc);
        }
        Command::TestIssuePresentation { input } => {
            let vc = ssi::credential::VerifiablePresentation::from_str(&input).unwrap();
            println!("{}", vc);
        }
    }
}
