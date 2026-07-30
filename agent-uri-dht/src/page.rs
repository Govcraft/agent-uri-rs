//! Paginated lookup results.

/// An opaque position in a paginated lookup.
///
/// A cursor is only meaningful to the backend that produced it and to a
/// subsequent lookup for the same query. Do not persist one across backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cursor(u32);

impl Cursor {
    /// Creates a cursor at the given position.
    #[must_use]
    pub const fn at(position: u32) -> Self {
        Self(position)
    }

    /// Returns the position this cursor resumes from.
    ///
    /// What a position indexes is the backend's business: an offset into a
    /// result set for the simulator, a key shard for a distributed backend.
    #[must_use]
    pub const fn position(self) -> u32 {
        self.0
    }
}

/// One page of lookup results.
///
/// A capability path can hold more registrations than a single DHT read can
/// return, so lookups page. `next` is `Some` only when the backend knows more
/// results remain; an empty page with `next: None` means the query is
/// exhausted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    items: Vec<T>,
    next: Option<Cursor>,
}

impl<T> Page<T> {
    /// Creates a page that completes the query.
    #[must_use]
    pub const fn complete(items: Vec<T>) -> Self {
        Self { items, next: None }
    }

    /// Creates a page with more results available from `next`.
    #[must_use]
    pub const fn partial(items: Vec<T>, next: Cursor) -> Self {
        Self {
            items,
            next: Some(next),
        }
    }

    /// Returns the results in this page.
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.items
    }

    /// Returns the cursor for the next page, if more results remain.
    #[must_use]
    pub const fn next_cursor(&self) -> Option<Cursor> {
        self.next
    }

    /// Returns true if more results remain beyond this page.
    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.next.is_some()
    }

    /// Returns the number of results in this page.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true if this page carries no results.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Consumes the page and returns its results.
    #[must_use]
    pub fn into_items(self) -> Vec<T> {
        self.items
    }
}

impl<T> IntoIterator for Page<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_page_has_no_cursor() {
        let page = Page::complete(vec![1, 2, 3]);
        assert_eq!(page.len(), 3);
        assert!(!page.has_more());
        assert!(page.next_cursor().is_none());
    }

    #[test]
    fn partial_page_carries_a_cursor() {
        let page = Page::partial(vec![1], Cursor::at(4));
        assert!(page.has_more());
        assert_eq!(page.next_cursor().unwrap().position(), 4);
    }

    #[test]
    fn empty_complete_page_is_exhausted_not_truncated() {
        // The distinction matters: an empty page that still has a cursor means
        // "nothing here, keep going", not "no such agents".
        let page: Page<u8> = Page::complete(vec![]);
        assert!(page.is_empty());
        assert!(!page.has_more());
    }

    #[test]
    fn empty_partial_page_still_reports_more() {
        let page: Page<u8> = Page::partial(vec![], Cursor::at(1));
        assert!(page.is_empty());
        assert!(page.has_more());
    }

    #[test]
    fn into_items_returns_the_results() {
        let page = Page::complete(vec![7, 8]);
        assert_eq!(page.into_items(), vec![7, 8]);
    }

    #[test]
    fn page_iterates() {
        let page = Page::complete(vec![1, 2, 3]);
        assert_eq!(page.into_iter().sum::<i32>(), 6);
    }
}
