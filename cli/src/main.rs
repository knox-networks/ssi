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
    /// Read the JSON string file in input_file and parse it into a VerifiableCredential. Then prints the VerifiableCredential
    TestIssueCredential {
        #[arg(short, long)]
        input_file: String,
    },
    /// Read the JSON string file in input_file and parse it into a VerifiablePresentation. Then prints the VerifiablePresentation
    TestIssuePresentation {
        #[arg(short, long)]
        input_file: String,
    },
    TestEd25519Signature2020 {
        #[arg(short, long)]
        input_file: String,
        #[arg(short, long)]
        key_pair_file: String,
    },
}

fn main() {
    let args = CliArguments::parse();
    match args.command {
        Command::TestIssueCredential {
            input_file: input_file_path,
        } => {
            let input = std::fs::read_to_string(input_file_path).unwrap();
            let vc = ssi::credential::VerifiableCredential::from_str(&input).unwrap();
            println!("{}", vc);
        }
        Command::TestIssuePresentation {
            input_file: input_file_path,
        } => {
            let input = std::fs::read_to_string(input_file_path).unwrap();
            let vc = ssi::credential::VerifiablePresentation::from_str(&input).unwrap();
            println!("{}", vc);
        }
        Command::TestEd25519Signature2020 {
            input_file,
            key_pair_file,
        } => {
            let input = std::fs::read_to_string(input_file).unwrap();
            let kp_file = std::fs::read_to_string(key_pair_file).unwrap();
            let kp: serde_json::Value = serde_json::from_str(&kp_file).unwrap();
            let private_key = kp
                .get("privateKeyMultibase")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string();
            let kp = ssi::signature::suite::ed25519_2020::Ed25519KeyPair::from_private_key(
                "test".to_string(),
                private_key,
            )
            .unwrap();
            let signer: ssi::signature::suite::ed25519_2020::Ed25519DidSigner = kp.into();
            let c = ssi::credential::Credential::from_str(&input).unwrap();
            let vc = c
                .try_into_verifiable_credential(
                    &signer,
                    ssi::signature::suite::VerificationRelation::AssertionMethod,
                )
                .unwrap();
            println!("{}", vc);
        }
    }
}
