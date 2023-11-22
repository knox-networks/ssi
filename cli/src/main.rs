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
        input_file_path: String,
    },
    TestIssuePresentation {
        #[arg(short, long)]
        input_file_path: String,
    },
}

fn main() {
    let args = CliArguments::parse();
    match args.command {
        Command::TestIssueCredential { input_file_path } => {
            //read the JSON string file in input_file_path and parse it into a VerifiableCredential
            //print the VerifiableCredential
            let input = std::fs::read_to_string(input_file_path).unwrap();
            let vc = ssi::credential::VerifiableCredential::from_str(&input).unwrap();
            println!("{}", vc);
        }
        Command::TestIssuePresentation { input_file_path } => {
            let input = std::fs::read_to_string(input_file_path).unwrap();
            let vc = ssi::credential::VerifiablePresentation::from_str(&input).unwrap();
            println!("{}", vc);
        }
    }
}
