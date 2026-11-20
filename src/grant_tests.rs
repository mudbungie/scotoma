use super::*;

#[test]
fn durations_are_a_count_and_a_unit() {
    assert_eq!(seconds("30s"), Some(30));
    assert_eq!(seconds("15m"), Some(900));
    assert_eq!(seconds("1h"), Some(3600));
    assert_eq!(seconds("2d"), Some(172_800));
    assert_eq!(seconds("0s"), Some(0));
    for bad in [
        "",
        "h",
        "1",
        "1w",
        "-1h",
        "1.5h",
        "1é",
        "99999999999999999999d",
        "9999999999999999999d",
    ] {
        assert_eq!(seconds(bad), None, "{bad}");
    }
}

#[test]
fn a_grant_covers_its_names_or_everything() {
    let narrow = Grant {
        id: "g".into(),
        names: vec!["a".into()],
        expires: u64::MAX,
    };
    assert!(narrow.covers("a") && !narrow.covers("b"));
    assert!(Grant::none().covers("anything"));
}

#[test]
fn a_grant_dies_at_its_expiry() {
    assert!(Grant::none().live());
    let dead = Grant {
        expires: now(),
        ..Grant::none()
    };
    assert!(!dead.live());
}
