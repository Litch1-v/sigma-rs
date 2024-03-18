

use nom::bytes::complete::{tag, take_till};
use nom::combinator::{fail, map};
use nom::{IResult};
use nom::branch::alt;
use nom::character::complete::{multispace0, multispace1};
use nom::character::{is_alphabetic};



use nom::multi::many0;
use nom::sequence::{delimited, preceded};

use crate::ast::ConditionExpr::{AllOfIdentifier, Identifier, Not, OneOfIdentifier, Parens};




#[derive(Debug)]
pub enum ConditionExpr {
    Identifier(String),
    OneOfIdentifier(Box<ConditionExpr>),
    AllOfIdentifier(Box<ConditionExpr>),
    Not(Box<ConditionExpr>),
    Or(Box<ConditionExpr>,Box<ConditionExpr>),
    And(Box<ConditionExpr>,Box<ConditionExpr>),
    Parens(Box<ConditionExpr>)
}


pub enum Operate{
    And,
    Or
}


fn parse_ident(expr: &str) -> IResult<&str, ConditionExpr> {
    // not keywords
    let (reminder,name) = take_till(|x:char|x.is_whitespace()||x == ')'||x == '(')(expr)?;
    if name.len() > 0 && name!="all" && name!="not" && !name.contains("(") && !name.contains(")") && is_alphabetic(name.as_bytes()[0]) {
        return Ok((reminder,Identifier(name.to_string())));
    }
    return fail(expr);
}
fn parse_one_of(expr: &str) -> IResult<&str, ConditionExpr> {
    map(preceded(tag("1 of "), parse_ident),|x|OneOfIdentifier(Box::new(x)))(expr)
}

fn parse_all_of(expr: &str) -> IResult<&str, ConditionExpr> {
    map(preceded(preceded(tag("all of"),multispace1), parse_ident),|x|AllOfIdentifier(Box::new(x)))(expr)
}


fn parse_parens(expr: &str)-> IResult<&str, ConditionExpr>{
    map( delimited(tag("("), parse_expr, tag(")")),|x|Parens(Box::new(x)) )(expr)
}
fn parse_factor(expr: &str)-> IResult<&str, ConditionExpr>{
    delimited(multispace0,alt((parse_ident,parse_parens,parse_not,parse_all_of,parse_one_of)),multispace0)(expr)
}
fn parse_not(expr: &str)-> IResult<&str, ConditionExpr> {
    map(preceded(
        preceded(tag("not"),multispace1),
        parse_factor
    ),|x|Not(Box::new(x)))(expr)
}
pub fn parse_expr(expr: &str)-> IResult<&str, ConditionExpr>{
    let (expr,init) = parse_factor(expr)?;
    let (expr,remainder) = many0(alt((
        map(preceded(preceded(tag("and"),multispace1), parse_factor),|x|(Operate::And,x)),
        map(preceded(preceded(tag("or"),multispace1), parse_factor),|x|(Operate::Or,x))
    )
    ))(expr)?;
    Ok((expr,fold_exprs(init,remainder)))
}


fn fold_exprs(initial: ConditionExpr, remainder: Vec<(Operate, ConditionExpr)>) -> ConditionExpr {
    remainder.into_iter().fold(initial, |acc, pair| {
        let (operate, expr) = pair;
        match operate {
            Operate::And => ConditionExpr::And(Box::new(acc), Box::new(expr)),
            Operate::Or => ConditionExpr::Or(Box::new(acc), Box::new(expr)),
        }
    })
}





#[cfg(test)]
mod test{
    use crate::ast::{parse_expr};

    #[test]
    pub fn test_parse_one_of(){
        println!("{:?}",parse_expr("(not test1) and ((1 of test1) or (all of test))"));
    }
}