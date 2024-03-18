# sigma-rs
A Rust implementation and parser of [Sigma rules](https://github.com/SigmaHQ/sigma). Useful for building your own detection pipelines.

## Features
- support complex condition like ```(not test*) and ((1 of test1) or (all of test))```
- regex build cache
## Usage
```rust
fn main() {
    let rule = r#"title: Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE#;
let json = r#"{
    "Image": "C:\\Windows\\system32\\certutil.exe",
    "ParentImage": "C:\\WINDOWS\\system32\\cmd.exe",
    "ProcessId": "10952",
    "utc_time": "2023-03-20 17:31:23",
    "ServerScore": "0",
    "CommandLine": "certutil  -urlcache \"-split\" \"-f\" \"http://transfer.sh/artifact.exe test.exe\"",
    "ParentCommandLine": "\"C:\\WINDOWS\\system32\\cmd.exe\"",
    "OriginalFile": "CertUtil.exe.mui",
    "log_type": "ProcessCreate"
  }"#;
    println!("{}", evaluate_sigma(parse_sigma(rule.to_string()), &source));
}
```

## Reference
- [sigma-go](https://github.com/bradleyjkemp/sigma-go) 
- [chainsaw](https://github.com/WithSecureLabs/chainsaw)