use crate::testing::{Scratch, Unlocked};
use crate::{Error, Request, Scotoma, wire};
use std::fs;
use std::os::unix::net::UnixStream;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// The log's lines, without their times.
fn lines(unlocked: &Unlocked) -> Vec<String> {
    let text = fs::read_to_string(unlocked.scratch.path.join("audit.tsv")).unwrap_or_default();
    let tail = |line: &str| line.split('\t').skip(1).collect::<Vec<_>>().join(" ");
    text.lines().map(tail).collect()
}

/// Ask for a grant over `pw` on another thread, as `actor`.
fn asking(unlocked: &Unlocked, actor: &str) -> JoinHandle<Result<String, Error>> {
    let client = Scotoma::open(&unlocked.scratch.path, actor).unwrap();
    thread::spawn(move || client.grant("1h", &["pw"], "to deploy"))
}

/// Run a command with no input; its exit code and what it printed.
fn runs(client: &Scotoma, command: &[&str]) -> Result<(u8, String), Error> {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = client.run(command, crate::testing::none(), &mut out, &mut err)?;
    Ok((code, String::from_utf8(out).unwrap()))
}

fn denied(result: Result<impl Sized, Error>, why: &str) -> bool {
    matches!(result, Err(Error::Denied(said)) if said.contains(why))
}

#[test]
fn the_console_is_asked_with_the_reason_and_every_outcome_is_logged() {
    let unlocked = Unlocked::new("y\nn\n");
    let client = unlocked.client();
    let token = client
        .grant("1h,3x,run", &["pw", "db"], "deploy\tthe \x1b[2Jsite ")
        .unwrap();
    let asked = "grant requested by tester: pw, db for 1h, 3 uses, run only\n\
                 reason: deploy the  [2Jsite\napprove? [y/N] ";
    assert!(unlocked.console.text().ends_with(asked));
    assert!(denied(client.grant("1h", &["pw"], "again"), "refused"));

    let log = lines(&unlocked);
    let id = log[0].split(' ').nth(3).unwrap().to_owned();
    assert_eq!(id.len(), 36);
    assert_eq!(
        log[..2],
        [
            format!("tester request pw,db {id} 1h,3x,run deploy the  [2Jsite"),
            format!("console grant pw,db {id} from root"),
        ]
    );
    assert!(log[2].starts_with("tester request pw ") && log[2].ends_with(" 1h again"));
    assert!(log[3].starts_with("console refuse pw ") && log[3].ends_with(" from root"));
    assert!(!log.iter().any(|line| line.contains(&token)));
}

#[test]
fn a_request_must_make_sense_before_anyone_is_asked() {
    let unlocked = Unlocked::new("y\n");
    let client = unlocked.client();
    assert!(denied(client.grant("soon", &["pw"], "why"), "duration"));
    assert!(denied(client.grant("1h", &[], "why"), "names its secrets"));
    assert!(denied(client.grant("1h", &["pw"], " \n"), "gives a reason"));
    let bad = client.grant("1h", &["two words"], "why");
    assert!(matches!(bad, Err(Error::Name(_))));
    assert!(!unlocked.console.text().contains("approve?"));
    assert!(lines(&unlocked).is_empty());
}

#[test]
fn nothing_is_stored_used_or_removed_without_a_live_grant_over_it() {
    let unlocked = Unlocked::new("");
    let client = unlocked.client();
    assert!(denied(client.set("pw", "hunter2"), "no grant"));
    unlocked.root().set("pw", "hunter2").unwrap();
    assert!(denied(client.substitute("x"), "no grant"));
    assert!(denied(client.remove("pw"), "no grant"));
    assert!(denied(
        client.clone().with_grant("made-up").remove("pw"),
        "no grant"
    ));

    let narrow = unlocked.granted(&["other"]);
    assert!(denied(narrow.set("pw", "mine"), "does not cover"));
    assert!(denied(narrow.remove("pw"), "does not cover"));
    narrow.set("other", "swordfish").unwrap();
    assert_eq!(client.names().unwrap(), ["other", "pw"]);

    let token = unlocked.root().grant("0s", &["pw"], "too late").unwrap();
    let spent = client.with_grant(&token);
    assert!(denied(spent.substitute("x"), "expired"));
    assert!(denied(runs(&spent, &["true"]), "expired"));
    assert!(denied(spent.grant("1h", &["pw"], "more"), "expired"));
}

#[test]
fn an_approver_on_the_socket_answers_and_ends_grants() {
    // The console has nothing to say: requests wait for the approver.
    let unlocked = Unlocked::new("");
    let (root, client) = (unlocked.root(), unlocked.client());
    root.set("pw", "hunter2").unwrap();
    assert!(denied(client.pending(), "no grant"));
    let holder = unlocked.granted(&["pw"]);
    assert!(denied(holder.pending(), "only the approver"));
    assert!(denied(holder.decide("anything", true), "only the approver"));

    let first = asking(&unlocked, "agent-a");
    let waiting = root.pending().unwrap();
    let expected = Request {
        id: waiting[0].id.clone(),
        actor: "agent-a".into(),
        names: vec!["pw".into()],
        limits: "1h".into(),
        reason: "to deploy".into(),
    };
    assert_eq!(waiting, [expected]);
    let policy = Scotoma::open(&unlocked.scratch.path, "policy").unwrap();
    let policy = policy.with_grant(&root_token(&unlocked));
    policy.decide(&waiting[0].id, true).unwrap();
    let token = first.join().unwrap().unwrap();
    let id = &waiting[0].id;
    assert_eq!(
        lines(&unlocked).last().unwrap(),
        &format!("policy grant pw {id} from root")
    );

    // Whoever presents the grant is logged as the name it was approved for.
    let impostor = Scotoma::open(&unlocked.scratch.path, "someone-else").unwrap();
    let agent = impostor.with_grant(&token);
    assert_eq!(agent.substitute("[scotoma:pw]").unwrap(), "hunter2");
    assert_eq!(
        lines(&unlocked).last().unwrap(),
        &format!("agent-a use pw {id} -")
    );
    let child = agent
        .clone()
        .with_grant(&agent.grant("5m", &["pw"], "delegate").unwrap());

    let second = asking(&unlocked, "agent-b");
    let waiting = root.pending().unwrap();
    root.decide(&waiting[0].id, false).unwrap();
    assert!(denied(second.join().unwrap(), "refused"));

    // A no to a live grant ends it and what was minted from it.
    assert!(denied(root.decide(id, true), "no open request"));
    assert!(denied(root.decide("root", false), "no open request"));
    assert!(denied(root.decide("nonsense", false), "no open request"));
    assert!(matches!(
        raw(&unlocked, &[b"decide", b"x", b"maybe"]),
        Err(Error::Denied(_))
    ));
    policy.decide(id, false).unwrap();
    assert_eq!(
        lines(&unlocked).last().unwrap(),
        &format!("policy revoke pw {id} -")
    );
    assert!(denied(agent.substitute("[scotoma:pw]"), "revoked"));
    assert!(denied(child.substitute("[scotoma:pw]"), "revoked"));
    assert!(denied(root.decide(id, false), "no open request"));
}

fn root_token(unlocked: &Unlocked) -> String {
    let console = unlocked.console.text();
    let token = console.split("approver token: ").nth(1).unwrap();
    token.lines().next().unwrap().to_owned()
}

/// Send a request as the approver and return the reply.
fn raw(unlocked: &Unlocked, args: &[&[u8]]) -> Result<Vec<u8>, Error> {
    let token = root_token(unlocked);
    let mut fields: Vec<&[u8]> = vec![b"tester", token.as_bytes()];
    fields.extend(args);
    let conn = UnixStream::connect(unlocked.scratch.path.join("socket")).unwrap();
    wire::send(&conn, wire::ASK, &wire::pack(&fields)).unwrap();
    let (tag, body) = wire::recv(&conn).unwrap();
    wire::outcome(tag, body)
}

#[test]
fn a_request_nobody_waits_for_is_dropped() {
    let unlocked = Unlocked::new("");
    let conn = UnixStream::connect(unlocked.scratch.path.join("socket")).unwrap();
    let fields: [&[u8]; 6] = [b"quitter", b"", b"grant", b"1h", b"why", b"pw"];
    wire::send(&conn, wire::ASK, &wire::pack(&fields)).unwrap();
    assert_eq!(unlocked.root().pending().unwrap().len(), 1);
    drop(conn);
    while !lines(&unlocked).iter().any(|line| line.contains("abandon")) {
        thread::sleep(Duration::from_millis(2));
    }
    let log = lines(&unlocked);
    assert!(log[1].starts_with("quitter abandon pw ") && log[1].ends_with(" -"));

    // Locking releases whoever is still waiting, asker and approver alike.
    let asker = asking(&unlocked, "patient");
    assert_eq!(unlocked.root().pending().unwrap().len(), 1);
    unlocked.client().lock().unwrap();
    assert!(denied(asker.join().unwrap(), "abandoned"));
}

#[test]
fn an_approver_waiting_at_lock_is_told_there_is_nothing() {
    let unlocked = Unlocked::new("");
    let root = unlocked.root();
    let waiting = thread::spawn(move || root.pending());
    thread::sleep(Duration::from_millis(20));
    unlocked.client().lock().unwrap();
    assert_eq!(waiting.join().unwrap().unwrap(), []);
}

#[test]
fn a_run_only_grant_runs_but_is_never_handed_the_value() {
    let unlocked = Unlocked::new("");
    let root = unlocked.root();
    root.set("pw", "hunter2").unwrap();
    let token = root.grant("1h,run", &["pw"], "testing").unwrap();
    let runner = unlocked.client().with_grant(&token);
    assert!(denied(runner.substitute("[scotoma:pw]"), "only runs"));
    let script = "test \"$1\" = hunter2 && echo \"$1\"";
    let ran = runs(&runner, &["sh", "-c", script, "sh", "[scotoma:pw]"]);
    assert_eq!(ran.unwrap(), (0, "[scotoma:pw]\n".to_owned()));
}

#[test]
fn a_grant_minted_from_a_grant_asks_nobody_and_is_bound_by_both() {
    let unlocked = Unlocked::new("");
    let root = unlocked.root();
    root.set("pw", "hunter2").unwrap();
    root.set("other", "swordfish").unwrap();
    let parent = unlocked.granted(&["pw"]);
    let token = parent
        .grant("1x,run", &["pw", "other"], "for the helper")
        .unwrap();
    let child = parent.clone().with_grant(&token);
    assert!(!unlocked.console.text().contains("approve?"));
    let log = lines(&unlocked);
    let parent_id = log[log.len() - 3].split(' ').nth(3).unwrap();
    assert!(log[log.len() - 2].starts_with("tester request pw,other "));
    assert!(log[log.len() - 1].starts_with("tester grant pw,other "));
    assert!(log[log.len() - 1].ends_with(&format!(" from {parent_id}")));

    // Wider on paper, no wider in fact; and a refusal costs no use.
    assert!(denied(runs(&child, &["echo", "[scotoma:other]"]), "cover"));
    assert!(denied(child.substitute("[scotoma:pw]"), "only runs"));
    assert!(matches!(
        runs(&child, &["echo", "[scotoma:pw]"]),
        Ok((0, _))
    ));
    // Its one use is spent; the parent's are not.
    assert!(denied(child.substitute("x"), "used up"));
    assert!(denied(child.grant("1h", &["pw"], "more"), "used up"));
    assert_eq!(parent.substitute("[scotoma:pw]").unwrap(), "hunter2");
}

#[test]
fn a_grant_needs_entropy_and_a_log_that_can_be_written() {
    let scratch = Scratch::new();
    let entropy = scratch.path.join("entropy");
    fs::write(&entropy, [5; 72]).unwrap();
    let unlocked = Unlocked::start(scratch, "pw\npw\n", &entropy);
    fs::remove_file(&entropy).unwrap();
    let starved = unlocked.root().grant("1h", &["pw"], "why");
    assert!(matches!(starved, Err(Error::Io { .. })));

    let unlocked = Unlocked::new("");
    let root = unlocked.root();
    let live = root.grant("1h", &["pw"], "to end later").unwrap();
    let id = lines(&unlocked)[0].split(' ').nth(3).unwrap().to_owned();
    let asker = asking(&unlocked, "agent-a");
    let waiting = root.pending().unwrap();
    let log = unlocked.scratch.path.join("audit.tsv");
    fs::remove_file(&log).unwrap();
    fs::create_dir(&log).unwrap();
    // Approved, but it cannot be recorded: no grant.
    root.decide(&waiting[0].id, true).unwrap();
    assert!(matches!(asker.join().unwrap(), Err(Error::Io { .. })));
    assert!(matches!(root.decide(&id, false), Err(Error::Io { .. })));
    assert!(matches!(
        root.grant("1h", &["pw"], "why"),
        Err(Error::Io { .. })
    ));
    drop(live);
}
