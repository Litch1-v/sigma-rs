use std::collections::HashMap;
use std::process::id;
use anyhow::anyhow;
use glob_match::glob_match;
use nom::error::ParseError;
use regex::Regex;
use serde_derive::Deserialize;
use serde_json::Value;
use serde_yaml::{Mapping};
use crate::ast::{ConditionExpr, parse_expr};
use crate::evaluate::Matcher::{ContainsMatcher, EndsWith, EqualMatcher, ReMatcher, StartsWith};

pub fn evaluate_condition_expr(expr:Box<ConditionExpr>,condition_part_results:&HashMap<String,bool>) -> bool{
    match *expr{
        ConditionExpr::Not(expr) => {
            return !evaluate_condition_expr(expr,condition_part_results);
        }
        ConditionExpr::Or(factor1,factor2) =>{
            return evaluate_condition_expr(factor1,condition_part_results) || evaluate_condition_expr(factor2,condition_part_results);
        }
        ConditionExpr::And(factor1,factor2) =>{
            return evaluate_condition_expr(factor1,condition_part_results) && evaluate_condition_expr(factor2,condition_part_results);
        }
        ConditionExpr::Identifier(ident) => {
            return condition_part_results.get(ident.as_str()).unwrap_or(&false).clone();
        }
        ConditionExpr::OneOfIdentifier(one_of_pattern) =>{
            if let ConditionExpr::Identifier(ident) = *one_of_pattern{
                for (condition_part_name,result) in condition_part_results{
                    if glob_match(&ident,condition_part_name){
                        if *result {
                            return true;
                        }
                    }
                }
                return false;
            }
        }
        ConditionExpr::Parens(expr) =>{
            return evaluate_condition_expr(expr,condition_part_results);
        }
        ConditionExpr::AllOfIdentifier(all_of_pattern) =>{
            if let ConditionExpr::Identifier(ident) = *all_of_pattern{
                for (condition_part_name,result) in condition_part_results{
                    if glob_match(&ident,condition_part_name){
                        if !result {
                            return false;
                        }
                    }
                }
                return true;
            }
        }
    }
    false

}


#[derive(Clone, Deserialize,Debug)]
pub struct Header {
    // server_rule_name
    pub title: String,
    // server_rule_description
    pub description: String,
    #[serde(default)]
    pub action: Option<String>, // kill 杀死执行行为的进程（该行为为高危）/block 拦截该行为（该行为为高危/ sus_kill (仅在严格模式（阻断所有的情况下) // sus_block 仅在严格模式（阻断所有的情况下）
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub references: Option<Vec<String>>,
    #[serde(default)]
    pub keyword: Option<Mapping>
}
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Detection {
    #[serde(default)]
    pub condition: Option<serde_yaml::Value>,
    #[serde(flatten)]
    pub identifiers: Mapping,
}
#[derive(Clone, Deserialize,Debug)]
pub struct Sigma {
    #[serde(default, flatten)]
    pub header: Option<Header>,
    #[serde(default)]
    pub detection: Option<Detection>,
}


#[derive(Debug)]
pub enum Matcher {
    EqualMatcher(Vec<String>),
    ContainsMatcher(Vec<String>),
    ReMatcher(Vec<Regex>),
    StartsWith(Vec<String>),
    EndsWith(Vec<String>)
}

impl Matcher{
    pub fn match_any(&self,compare_value: &Value) -> bool{
        return match self {
            EqualMatcher(patterns) => {
                if compare_value.is_string() {
                    return patterns.iter().any(|x| compare_value.as_str().unwrap().to_lowercase().contains(&x.to_lowercase()));
                }
                false
            }
            ContainsMatcher(patterns) => {
                if compare_value.is_string() {
                    return patterns.iter().any(|x| compare_value.as_str().unwrap().to_lowercase().contains(&x.to_lowercase()));
                }
                false
            }
            ReMatcher(patterns) => {
                if compare_value.is_string() {
                    return patterns.iter().any(|x| x.is_match(compare_value.as_str().unwrap()));
                }
                false
            }
            StartsWith(patterns) => {
                if compare_value.is_string() {
                    return patterns.iter().any(|x| compare_value.as_str().unwrap().starts_with(x));
                }
                false
            }
            EndsWith(patterns) => {
                if compare_value.is_string() {
                    return patterns.iter().any(|x| compare_value.as_str().unwrap().ends_with(x));
                }
                false
            }
        }
    }

    pub fn match_all(&self,compare_value: &Value) -> bool{
        match self{
            ContainsMatcher(patterns) => {
                if compare_value.is_string() {
                    return patterns.iter().all(|x| compare_value.as_str().unwrap().to_lowercase().contains(&x.to_lowercase()));
                }
                return false;
            }
            ReMatcher(patterns) => {
                if compare_value.is_string() {
                    return patterns.iter().all(|x| x.is_match(compare_value.as_str().unwrap()));
                }
                return false;
            },

            _ => {}
        }
        return false;
    }
}




struct DetectionRule{
    pub identifier: HashMap<String, FieldMatcher>,
    pub condition: ConditionExpr,
}




#[derive(Debug)]
pub struct FieldMatcher {
    field: String,
    matcher: Matcher,
    must_all: bool
}

pub fn parse_identifier(identifier_map:Mapping) -> anyhow::Result<HashMap<String,Vec<FieldMatcher>>> {
    let mut ident_map :HashMap<String,Vec<FieldMatcher>> = HashMap::new();
    for (ident,rule) in identifier_map{
        let ident = ident.as_str().unwrap_or_default();
        let mut rule_vec:Vec<FieldMatcher> = vec![];
        // 如果是一个list的形式，里面每一个都是一个FiledMatcher
        if rule.is_sequence(){
            for field_map in rule.as_sequence().unwrap(){
                if let Some(map) = field_map.as_mapping(){
                    if let Ok(field_matcher) = parse_field_matcher(map){
                        rule_vec.extend(field_matcher);
                    }
                }
            }
        }
        if rule.is_mapping(){
            if let Ok(field_matcher) = parse_field_matcher(rule.as_mapping().unwrap()){
                rule_vec.extend(field_matcher);
            }
        }
        ident_map.insert(ident.to_string(),rule_vec);
    }
    return  Ok(ident_map);
}



fn parse_field_matcher(field_map: &Mapping) -> anyhow::Result<Vec<FieldMatcher>> {
    let mut field_matcher_vec = vec![];
    let mut filed_map_iter = field_map.iter();
    while let Some((key,field_map_values)) = filed_map_iter.next() {
        let mut values = vec![];
        if field_map_values.is_sequence() {
            values = field_map_values.as_sequence().unwrap().to_vec().iter().map(|x| x.as_str().unwrap_or_default().to_string()).filter(|x| x != "").collect();
        }
        if field_map_values.is_string(){
            values = vec![field_map_values.as_str().unwrap().to_string()];
        }
        if !values.is_empty() {
            if let Some(key) = key.as_str() {
                let key_vec = key.split("|").collect::<Vec<_>>();
                let mut key_iter = key_vec.iter();
                if let Some(field_name) = key_iter.next(){
                    let mut matcher = FieldMatcher {
                        field: field_name.to_string(),
                        matcher: EqualMatcher(values.clone()),
                        must_all: false
                    };
                    while let Some(match_type) = key_iter.next() {
                        match match_type.to_lowercase().as_str() {
                            "all" => {
                                matcher.must_all = true;
                            },
                            "contains" => {
                                matcher.matcher = ContainsMatcher(values.clone());
                            },
                            "re" => {
                                let mut re_vec = vec![];
                                for value in &values {
                                    re_vec.push(Regex::new(&value)?);
                                }
                                matcher.matcher = ReMatcher(re_vec);
                            },
                            "startswith" => {
                                matcher.matcher = StartsWith(values.clone());
                            },
                            "endswith" => {
                                matcher.matcher = EndsWith(values.clone());
                            }
                            _ => {}
                        }
                    }
                    field_matcher_vec.push(matcher);
                }

            }
        }
    }
    return Ok(field_matcher_vec);
}

impl FieldMatcher {
    pub(crate) fn evaluate_field_matcher(&self, source_map: &HashMap<String,Value>) -> bool{
        if let Some(compare_value) = source_map.get(&self.field){
            return if self.must_all {
                self.matcher.match_all(compare_value)
            } else {
                self.matcher.match_any(compare_value)
            }
        }
        false
    }
}

#[derive(Default)]
pub struct Rule{
    pub header:Option<Header>,
    pub condition: Option<ConditionExpr>,
    pub ident_map: HashMap<String,Vec<FieldMatcher>>
}







