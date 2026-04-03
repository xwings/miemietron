use aho_corasick::AhoCorasick;
use std::collections::HashMap;

/// Domain matcher using exact match, suffix trie, and keyword Aho-Corasick.
pub struct DomainMatcher {
    exact: HashMap<String, String>,
    suffixes: Vec<(String, String)>, // (suffix, target) - reversed domain segments
    keywords: Option<AhoCorasick>,
    keyword_targets: Vec<String>,
}

impl DomainMatcher {
    pub fn new(
        exact: HashMap<String, String>,
        suffixes: Vec<(String, String)>,
        keywords: Vec<(String, String)>,
    ) -> Self {
        let (keywords_ac, keyword_targets) = if !keywords.is_empty() {
            let patterns: Vec<&str> = keywords.iter().map(|(k, _)| k.as_str()).collect();
            let targets: Vec<String> = keywords.iter().map(|(_, t)| t.clone()).collect();
            (AhoCorasick::new(&patterns).ok(), targets)
        } else {
            (None, vec![])
        };

        Self {
            exact,
            suffixes,
            keywords: keywords_ac,
            keyword_targets,
        }
    }

    pub fn lookup(&self, domain: &str) -> Option<String> {
        self.lookup_detailed(domain)
            .map(|(_rule_type, _payload, target)| target)
    }

    /// Like `lookup` but returns (rule_type, matched_payload, target).
    pub fn lookup_detailed(&self, domain: &str) -> Option<(String, String, String)> {
        let domain_lower = domain.to_lowercase();

        // 1. Exact match (O(1))
        if let Some(target) = self.exact.get(&domain_lower) {
            return Some(("DOMAIN".to_string(), domain_lower, target.clone()));
        }

        // 2. Suffix match
        for (suffix, target) in &self.suffixes {
            if domain_lower.ends_with(suffix) || domain_lower == suffix.trim_start_matches('.') {
                let payload = suffix.trim_start_matches('.').to_string();
                return Some(("DOMAIN-SUFFIX".to_string(), payload, target.clone()));
            }
        }

        // 3. Keyword match (Aho-Corasick - single pass)
        if let Some(ref ac) = self.keywords {
            if let Some(mat) = ac.find(&domain_lower) {
                let idx = mat.pattern().as_usize();
                // Extract the matched keyword pattern from the input
                let keyword = domain_lower[mat.start()..mat.end()].to_string();
                return Some((
                    "DOMAIN-KEYWORD".to_string(),
                    keyword,
                    self.keyword_targets[idx].clone(),
                ));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_matcher() -> DomainMatcher {
        let mut exact = HashMap::new();
        exact.insert("exact.example.com".to_string(), "proxy-exact".to_string());

        let suffixes = vec![
            (".google.com".to_string(), "proxy-suffix".to_string()),
            (".github.io".to_string(), "proxy-gh".to_string()),
        ];

        let keywords = vec![
            ("facebook".to_string(), "proxy-keyword".to_string()),
            ("twitter".to_string(), "proxy-keyword2".to_string()),
        ];

        DomainMatcher::new(exact, suffixes, keywords)
    }

    #[test]
    fn exact_match() {
        let m = make_matcher();
        assert_eq!(
            m.lookup("exact.example.com"),
            Some("proxy-exact".to_string())
        );
    }

    #[test]
    fn exact_match_case_insensitive() {
        let m = make_matcher();
        assert_eq!(
            m.lookup("EXACT.EXAMPLE.COM"),
            Some("proxy-exact".to_string())
        );
    }

    #[test]
    fn suffix_match() {
        let m = make_matcher();
        assert_eq!(m.lookup("www.google.com"), Some("proxy-suffix".to_string()));
        assert_eq!(
            m.lookup("mail.google.com"),
            Some("proxy-suffix".to_string())
        );
    }

    #[test]
    fn suffix_match_bare_domain() {
        let m = make_matcher();
        // "google.com" == ".google.com".trim_start_matches('.')
        assert_eq!(m.lookup("google.com"), Some("proxy-suffix".to_string()));
    }

    #[test]
    fn keyword_match() {
        let m = make_matcher();
        assert_eq!(
            m.lookup("www.facebook.com"),
            Some("proxy-keyword".to_string())
        );
        assert_eq!(
            m.lookup("m.twitter.com"),
            Some("proxy-keyword2".to_string())
        );
    }

    #[test]
    fn keyword_match_case_insensitive() {
        let m = make_matcher();
        assert_eq!(
            m.lookup("WWW.FACEBOOK.COM"),
            Some("proxy-keyword".to_string())
        );
    }

    #[test]
    fn no_false_positives() {
        let m = make_matcher();
        assert_eq!(m.lookup("example.org"), None);
        assert_eq!(m.lookup("notgoogle.com"), None);
        assert_eq!(m.lookup("random.xyz"), None);
    }

    #[test]
    fn empty_matcher() {
        let m = DomainMatcher::new(HashMap::new(), vec![], vec![]);
        assert_eq!(m.lookup("anything.com"), None);
    }
}
