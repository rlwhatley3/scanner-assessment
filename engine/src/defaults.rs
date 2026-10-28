//! The built-in rule set, seeded as the first rule set version. It lives in
//! `rule_sets/default.json` in the same shape the API sends for a scan, so loading it exercises
//! that contract. Every rule is ordinary data: users can edit, disable, or remove any of them.
//! See `engine/README.md` for what each rule catches, what it misses, and why.

use crate::rules::RuleSet;

const DEFAULT_RULE_SET: &str = include_str!("../rule_sets/default.json");

pub fn default_rule_set() -> RuleSet {
    serde_json::from_str(DEFAULT_RULE_SET)
        .expect("rule_sets/default.json matches the rule set contract")
}
