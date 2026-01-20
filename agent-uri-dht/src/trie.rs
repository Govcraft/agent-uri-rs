//! Path trie for efficient prefix matching on capability paths.

use std::collections::HashMap;

use agent_uri::{CapabilityPath, PathSegment};

/// Trie structure for efficient prefix matching on capability paths.
///
/// Supports:
/// - O(d) insert where d is path depth
/// - O(d) exact lookup
/// - O(d + n) prefix lookup where n is the number of descendants
///
/// # Type Parameter
///
/// * `V` - The value type stored at each path node
///
/// # Examples
///
/// ```
/// use agent_uri::CapabilityPath;
/// use agent_uri_dht::PathTrie;
///
/// let mut trie: PathTrie<String> = PathTrie::new();
///
/// let path1 = CapabilityPath::parse("assistant/chat").unwrap();
/// let path2 = CapabilityPath::parse("assistant/code").unwrap();
///
/// trie.insert(&path1, "Chat Agent".to_string());
/// trie.insert(&path2, "Code Agent".to_string());
///
/// // Exact lookup
/// let chat_agents = trie.get_exact(&path1);
/// assert_eq!(chat_agents.len(), 1);
///
/// // Prefix lookup for "assistant" finds both
/// let prefix = CapabilityPath::parse("assistant").unwrap();
/// let all_assistants = trie.get_prefix(&prefix);
/// assert_eq!(all_assistants.len(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct PathTrie<V> {
    /// Children indexed by path segment
    children: HashMap<String, PathTrie<V>>,
    /// Values stored at this node
    values: Vec<V>,
}

impl<V> Default for PathTrie<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> PathTrie<V> {
    /// Creates an empty trie.
    #[must_use]
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
            values: Vec::new(),
        }
    }

    /// Returns the number of values stored at this node.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns true if this node has no values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns the total number of values in this trie and all descendants.
    #[must_use]
    pub fn total_count(&self) -> usize {
        let mut count = self.values.len();
        for child in self.children.values() {
            count += child.total_count();
        }
        count
    }

    /// Returns the number of unique paths (nodes with values) in this trie.
    #[must_use]
    pub fn unique_paths(&self) -> usize {
        let mut count = usize::from(!self.values.is_empty());
        for child in self.children.values() {
            count += child.unique_paths();
        }
        count
    }

    /// Returns true if this node has children.
    #[must_use]
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }
}

impl<V: Clone> PathTrie<V> {
    /// Inserts a value at the given path.
    ///
    /// Multiple values can be stored at the same path.
    pub fn insert(&mut self, path: &CapabilityPath, value: V) {
        let segments = path.segments();
        self.insert_at_segments(segments, 0, value);
    }

    fn insert_at_segments(&mut self, segments: &[PathSegment], index: usize, value: V) {
        if index >= segments.len() {
            self.values.push(value);
            return;
        }

        let segment = segments[index].as_str().to_string();
        let child = self.children.entry(segment).or_default();
        child.insert_at_segments(segments, index + 1, value);
    }

    /// Returns values at the exact path (not including descendants).
    #[must_use]
    pub fn get_exact(&self, path: &CapabilityPath) -> Vec<&V> {
        let segments = path.segments();
        self.get_exact_at_segments(segments, 0)
    }

    fn get_exact_at_segments(&self, segments: &[PathSegment], index: usize) -> Vec<&V> {
        if index >= segments.len() {
            return self.values.iter().collect();
        }

        let segment = segments[index].as_str();
        match self.children.get(segment) {
            Some(child) => child.get_exact_at_segments(segments, index + 1),
            None => Vec::new(),
        }
    }

    /// Returns values at the path and all descendant paths (prefix match).
    #[must_use]
    pub fn get_prefix(&self, path: &CapabilityPath) -> Vec<&V> {
        let segments = path.segments();
        self.get_prefix_at_segments(segments, 0)
    }

    fn get_prefix_at_segments(&self, segments: &[PathSegment], index: usize) -> Vec<&V> {
        if index >= segments.len() {
            // We've reached the query path, collect this node and all descendants
            return self.collect_all();
        }

        let segment = segments[index].as_str();
        match self.children.get(segment) {
            Some(child) => child.get_prefix_at_segments(segments, index + 1),
            None => Vec::new(),
        }
    }

    /// Collects all values at this node and all descendants.
    fn collect_all(&self) -> Vec<&V> {
        let mut result: Vec<&V> = self.values.iter().collect();
        for child in self.children.values() {
            result.extend(child.collect_all());
        }
        result
    }

    /// Removes values at the path that match the predicate.
    ///
    /// Returns the number of values removed.
    pub fn remove<F>(&mut self, path: &CapabilityPath, predicate: F) -> usize
    where
        F: Fn(&V) -> bool,
    {
        let segments = path.segments();
        self.remove_at_segments(segments, 0, &predicate)
    }

    fn remove_at_segments<F>(
        &mut self,
        segments: &[PathSegment],
        index: usize,
        predicate: &F,
    ) -> usize
    where
        F: Fn(&V) -> bool,
    {
        if index >= segments.len() {
            let before = self.values.len();
            self.values.retain(|v| !predicate(v));
            return before - self.values.len();
        }

        let segment = segments[index].as_str().to_string();
        if let Some(child) = self.children.get_mut(&segment) {
            let removed = child.remove_at_segments(segments, index + 1, predicate);
            // Clean up empty children
            if child.is_empty() && !child.has_children() {
                self.children.remove(&segment);
            }
            removed
        } else {
            0
        }
    }

    /// Clears all values from the trie.
    pub fn clear(&mut self) {
        self.values.clear();
        self.children.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_trie_is_empty() {
        let trie: PathTrie<String> = PathTrie::new();
        assert!(trie.is_empty());
        assert_eq!(trie.len(), 0);
        assert_eq!(trie.total_count(), 0);
        assert_eq!(trie.unique_paths(), 0);
    }

    #[test]
    fn insert_and_get_exact() {
        let mut trie: PathTrie<String> = PathTrie::new();
        let path = CapabilityPath::parse("assistant/chat").unwrap();

        trie.insert(&path, "test".to_string());

        let results = trie.get_exact(&path);
        assert_eq!(results.len(), 1);
        assert_eq!(*results[0], "test");
    }

    #[test]
    fn multiple_values_at_same_path() {
        let mut trie: PathTrie<String> = PathTrie::new();
        let path = CapabilityPath::parse("assistant/chat").unwrap();

        trie.insert(&path, "agent1".to_string());
        trie.insert(&path, "agent2".to_string());

        let results = trie.get_exact(&path);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn get_exact_returns_empty_for_nonexistent_path() {
        let trie: PathTrie<String> = PathTrie::new();
        let path = CapabilityPath::parse("assistant/chat").unwrap();

        let results = trie.get_exact(&path);
        assert!(results.is_empty());
    }

    #[test]
    fn get_exact_does_not_include_descendants() {
        let mut trie: PathTrie<String> = PathTrie::new();

        let path1 = CapabilityPath::parse("assistant").unwrap();
        let path2 = CapabilityPath::parse("assistant/chat").unwrap();

        trie.insert(&path1, "assistant".to_string());
        trie.insert(&path2, "chat".to_string());

        let results = trie.get_exact(&path1);
        assert_eq!(results.len(), 1);
        assert_eq!(*results[0], "assistant");
    }

    #[test]
    fn get_prefix_includes_descendants() {
        let mut trie: PathTrie<String> = PathTrie::new();

        let path1 = CapabilityPath::parse("assistant").unwrap();
        let path2 = CapabilityPath::parse("assistant/chat").unwrap();
        let path3 = CapabilityPath::parse("assistant/code").unwrap();

        trie.insert(&path1, "assistant".to_string());
        trie.insert(&path2, "chat".to_string());
        trie.insert(&path3, "code".to_string());

        let results = trie.get_prefix(&path1);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn get_prefix_at_leaf_returns_only_that_node() {
        let mut trie: PathTrie<String> = PathTrie::new();

        let path1 = CapabilityPath::parse("assistant").unwrap();
        let path2 = CapabilityPath::parse("assistant/chat").unwrap();

        trie.insert(&path1, "assistant".to_string());
        trie.insert(&path2, "chat".to_string());

        let results = trie.get_prefix(&path2);
        assert_eq!(results.len(), 1);
        assert_eq!(*results[0], "chat");
    }

    #[test]
    fn get_prefix_returns_empty_for_nonexistent_path() {
        let trie: PathTrie<String> = PathTrie::new();
        let path = CapabilityPath::parse("nonexistent").unwrap();

        let results = trie.get_prefix(&path);
        assert!(results.is_empty());
    }

    #[test]
    fn remove_matching_values() {
        let mut trie: PathTrie<String> = PathTrie::new();
        let path = CapabilityPath::parse("assistant/chat").unwrap();

        trie.insert(&path, "agent1".to_string());
        trie.insert(&path, "agent2".to_string());

        let removed = trie.remove(&path, |v| v == "agent1");
        assert_eq!(removed, 1);

        let results = trie.get_exact(&path);
        assert_eq!(results.len(), 1);
        assert_eq!(*results[0], "agent2");
    }

    #[test]
    fn remove_all_values_cleans_up_node() {
        let mut trie: PathTrie<String> = PathTrie::new();
        let path = CapabilityPath::parse("assistant/chat").unwrap();

        trie.insert(&path, "agent1".to_string());

        let removed = trie.remove(&path, |_| true);
        assert_eq!(removed, 1);
        assert_eq!(trie.total_count(), 0);
    }

    #[test]
    fn remove_from_nonexistent_path_returns_zero() {
        let mut trie: PathTrie<String> = PathTrie::new();
        let path = CapabilityPath::parse("nonexistent").unwrap();

        let removed = trie.remove(&path, |_| true);
        assert_eq!(removed, 0);
    }

    #[test]
    fn total_count_includes_all_descendants() {
        let mut trie: PathTrie<String> = PathTrie::new();

        let path1 = CapabilityPath::parse("assistant").unwrap();
        let path2 = CapabilityPath::parse("assistant/chat").unwrap();
        let path3 = CapabilityPath::parse("assistant/code").unwrap();
        let path4 = CapabilityPath::parse("workflow").unwrap();

        trie.insert(&path1, "a".to_string());
        trie.insert(&path2, "b".to_string());
        trie.insert(&path3, "c".to_string());
        trie.insert(&path4, "d".to_string());

        assert_eq!(trie.total_count(), 4);
    }

    #[test]
    fn unique_paths_counts_nodes_with_values() {
        let mut trie: PathTrie<String> = PathTrie::new();

        let path1 = CapabilityPath::parse("assistant").unwrap();
        let path2 = CapabilityPath::parse("assistant/chat").unwrap();

        trie.insert(&path1, "a".to_string());
        trie.insert(&path2, "b".to_string());
        trie.insert(&path2, "c".to_string()); // Same path, different value

        assert_eq!(trie.unique_paths(), 2);
    }

    #[test]
    fn clear_removes_everything() {
        let mut trie: PathTrie<String> = PathTrie::new();

        let path = CapabilityPath::parse("assistant/chat").unwrap();
        trie.insert(&path, "test".to_string());

        trie.clear();

        assert!(trie.is_empty());
        assert_eq!(trie.total_count(), 0);
        assert!(!trie.has_children());
    }

    #[test]
    fn default_creates_empty_trie() {
        let trie: PathTrie<String> = PathTrie::default();
        assert!(trie.is_empty());
    }

    #[test]
    fn deep_hierarchy() {
        let mut trie: PathTrie<String> = PathTrie::new();

        let path1 = CapabilityPath::parse("a/b/c/d").unwrap();
        let path2 = CapabilityPath::parse("a/b/c").unwrap();
        let path3 = CapabilityPath::parse("a/b").unwrap();
        let path4 = CapabilityPath::parse("a").unwrap();

        trie.insert(&path1, "deep".to_string());
        trie.insert(&path2, "mid".to_string());
        trie.insert(&path3, "shallow".to_string());
        trie.insert(&path4, "root".to_string());

        // Prefix query at root should find all
        let results = trie.get_prefix(&path4);
        assert_eq!(results.len(), 4);

        // Prefix query at mid should find mid and deep
        let results = trie.get_prefix(&path2);
        assert_eq!(results.len(), 2);
    }
}
