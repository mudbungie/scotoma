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
        ..Grant::none()
    };
    assert!(narrow.covers("a") && !narrow.covers("b"));
    assert!(Grant::none().covers("anything"));
}

fn all(seconds: u64, uses: u64, run_only: bool) -> Limits {
    Limits {
        seconds,
        uses,
        run_only,
    }
}

#[test]
fn limits_are_terms_joined_by_commas() {
    assert_eq!(limits("1h"), Some(all(3600, u64::MAX, false)));
    assert_eq!(limits("3x"), Some(all(u64::MAX, 3, false)));
    assert_eq!(limits("run"), Some(all(u64::MAX, u64::MAX, true)));
    assert_eq!(limits("run,2x,30s"), Some(all(30, 2, true)));
    for bad in ["", "soon", "1h,", "manyx", "x", "1h 3x", "-1x"] {
        assert_eq!(limits(bad), None, "{bad}");
    }
    assert_eq!(describe("1h,3x,run"), "1h, 3 uses, run only");
    assert_eq!(describe("1x"), "1 use");
}

#[test]
fn a_grant_minted_from_another_is_bound_by_both() {
    let parent = Grant::mint("p".into(), vec!["a".into()], &all(3600, 1, true), None);
    let child = Grant::mint("c".into(), Vec::new(), &all(60, 5, false), Some(parent));
    assert!(child.covers("a") && !child.covers("b"));
    assert!(child.live() && !child.reveals());
    assert!(Grant::none().reveals());
    // The parent's one use is the child's too.
    assert!(child.charge());
    assert!(!child.charge() && !child.live());

    let spent = Grant::mint("s".into(), Vec::new(), &all(60, 0, false), None);
    assert!(!spent.charge() && !spent.live() && spent.reveals());
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
