use super::*;

fn entry(find: &str, put: &str) -> Entry {
    Entry {
        find: find.into(),
        put: put.into(),
        secret: put.into(),
        handle: "-".into(),
    }
}

fn filter(pairs: &[(&str, &str)]) -> Filter {
    Filter::new(pairs.iter().map(|(find, put)| entry(find, put)).collect())
}

/// Feed `chunks` and return the whole output and the names that fired.
fn run(pairs: &[(&str, &str)], chunks: &[&str]) -> (String, Vec<String>) {
    let mut filter = filter(pairs);
    let mut out = Vec::new();
    let mut names = Vec::new();
    let ends = chunks.iter().map(|_| false).chain([true]);
    for (chunk, last) in chunks.iter().chain(&[""]).zip(ends) {
        let (bytes, fired) = filter.feed(chunk.as_bytes(), last);
        out.extend(bytes);
        names.extend(fired.into_iter().map(|entry| entry.secret));
    }
    (String::from_utf8(out).unwrap(), names)
}

#[test]
fn replaces_every_occurrence_and_reports_each() {
    let (out, names) = run(&[("cat", "X")], &["a cat, a cat"]);
    assert_eq!(out, "a X, a X");
    assert_eq!(names, ["X", "X"]);
}

#[test]
fn text_without_a_match_passes_through() {
    assert_eq!(run(&[("cat", "X")], &["dog"]).0, "dog");
    assert_eq!(run(&[], &["dog"]).0, "dog");
}

#[test]
fn the_longest_entry_wins() {
    let table = [("ab", "SHORT"), ("abc", "LONG")];
    assert_eq!(run(&table, &["abc ab abd"]).0, "LONG SHORT SHORTd");
}

#[test]
fn a_match_straddles_any_chunk_boundary() {
    let whole = run(&[("secret", "X")], &["a secret b"]).0;
    for cut in 0..10 {
        let (head, tail) = "a secret b".split_at(cut);
        assert_eq!(run(&[("secret", "X")], &[head, tail]).0, whole);
    }
    assert_eq!(
        run(&[("secret", "X")], &["s", "e", "c", "r", "e", "t"]).0,
        "X"
    );
}

#[test]
fn a_held_prefix_is_released_when_it_stops_matching() {
    let mut filter = filter(&[("secret", "X")]);
    assert_eq!(filter.feed(b"a sec", false).0, b"a ");
    assert_eq!(filter.feed(b"ond", false).0, b"second");
}

#[test]
fn the_end_decides_what_was_held() {
    let table = [("ab", "SHORT"), ("abc", "LONG")];
    // "ab" could still grow into "abc": held, then resolved at the end.
    let mut filter = filter(&table);
    assert_eq!(filter.feed(b"ab", false), (vec![], vec![]));
    let (out, fired) = filter.feed(b"", true);
    assert_eq!(out, b"SHORT");
    assert_eq!(fired, [entry("ab", "SHORT")]);
    // A bare prefix of an entry is not a match.
    assert_eq!(run(&[("secret", "X")], &["sec"]).0, "sec");
}

#[test]
fn empty_and_duplicate_entries_are_dropped() {
    let filter = filter(&[("", "EMPTY"), ("a", "FIRST"), ("a", "SECOND")]);
    assert_eq!(filter.entries, [entry("a", "FIRST")]);
}

#[test]
fn overlapping_entries_resolve_leftmost_first() {
    let table = [("abc", "1"), ("bcd", "2"), ("b", "3")];
    assert_eq!(run(&table, &["abcd bcd xb"]).0, "1d 2 x3");
}
