use super::*;

fn text(forms: Vec<Vec<u8>>) -> Vec<String> {
    forms
        .into_iter()
        .map(|form| String::from_utf8(form).unwrap())
        .collect()
}

#[test]
fn json_escapes_as_the_serializers_do() {
    assert_eq!(json("plain"), "plain");
    assert_eq!(
        json("\"\\\n\r\t\u{8}\u{c}\u{1}é"),
        "\\\"\\\\\\n\\r\\t\\b\\f\\u0001é"
    );
}

#[test]
fn percent_encoding_comes_in_the_cases_encoders_write() {
    assert_eq!(percent("p@ss w/rd-._~", true, false), "p%40ss%20w%2Frd-._~");
    assert_eq!(percent("p@ss w/rd", false, false), "p%40ss%20w%2frd");
    assert_eq!(percent("p@ss w/rd", true, true), "p%40ss+w%2Frd");
    assert_eq!(percent("é", false, true), "%c3%a9");
}

#[test]
fn a_base64_fragment_is_what_the_value_alone_decides() {
    // base64("admin:hunter2"), ("abc:hunter2"), ("a:hunter2"): the value
    // after six, four and two bytes, which is every alignment.
    let runs = ["YWRtaW46aHVudGVyMg==", "YWJjOmh1bnRlcjI=", "YTpodW50ZXIy"];
    let fragments: Vec<String> = text(
        (0..3)
            .map(|lead| fragment(b"hunter2", lead, STANDARD))
            .collect(),
    );
    assert_eq!(fragments, ["aHVudGVyM", "h1bnRlcj", "odW50ZXIy"]);
    for (run, fragment) in runs.iter().zip(&fragments) {
        assert!(run.contains(fragment.as_str()));
    }
    assert_eq!(fragment(b"??>>??>>", 1, STANDARD), b"8/Pj4/Pz4+");
    assert_eq!(fragment(b"??>>??>>", 1, URL_SAFE), b"8_Pj4_Pz4-");
    // Too short to tell from chance.
    assert_eq!(fragment(b"abc", 0, STANDARD), b"");
}

#[test]
fn every_form_of_a_value_is_looked_for() {
    let forms = text(of("p@ss \"w\"rd"));
    for form in [
        "p@ss \"w\"rd",
        "p@ss \\\"w\\\"rd",
        "p%40ss%20%22w%22rd",
        "p%40ss+%22w%22rd",
        "cEBzcyAidyJyZ",
    ] {
        assert!(forms.iter().any(|found| found == form), "{form}");
    }
    assert_eq!(forms.len(), 12);
    // A short value has no base64 forms.
    assert_eq!(of("ab").len(), 6);
}
