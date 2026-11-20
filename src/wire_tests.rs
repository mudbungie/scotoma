use super::*;

#[test]
fn a_frame_round_trips() {
    let mut pipe = Vec::new();
    send(&mut pipe, OK, b"hello").unwrap();
    send(&mut pipe, END, b"").unwrap();
    assert_eq!(pipe, b".\0\0\0\x05hello$\0\0\0\0");
    let mut from = pipe.as_slice();
    assert_eq!(recv(&mut from).unwrap(), (OK, b"hello".to_vec()));
    assert_eq!(recv(&mut from).unwrap(), (END, Vec::new()));
    assert!(recv(&mut from).is_err());
}

#[test]
fn a_broken_frame_is_an_error() {
    assert!(recv(&mut &b".\0\0\0\x05hel"[..]).is_err());
    let oversized = [
        &[OK],
        (u32::try_from(LIMIT).unwrap() + 1).to_be_bytes().as_slice(),
    ]
    .concat();
    assert_eq!(
        recv(&mut oversized.as_slice()).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn a_field_list_round_trips() {
    let fields: [&[u8]; 3] = [b"one", b"", b"\xff\0two"];
    assert_eq!(unpack(&pack(&fields)).unwrap(), fields);
    assert_eq!(unpack(b"").unwrap(), Vec::<Vec<u8>>::new());
    assert_eq!(unpack(b"\0\0\0\0\x09short"), None);
}

#[test]
fn every_error_survives_the_socket() {
    let errors = [
        Error::Name("n".into()),
        Error::Unknown("u".into()),
        Error::Empty,
        Error::Leak("l".into()),
        Error::Denied("d".into()),
        Error::Sealed,
        Error::Locked,
        Error::Password,
    ];
    for error in errors {
        let (tag, text) = refusal(&error);
        let back = outcome(tag, text.into_bytes()).unwrap_err();
        assert_eq!(back.to_string(), error.to_string());
    }
    let io = Error::io("the/path")(io::Error::other("boom"));
    let (tag, text) = refusal(&io);
    let back = outcome(tag, text.into_bytes()).unwrap_err();
    assert_eq!(back.to_string(), "resident: \"the/path\": boom");
    assert_eq!(outcome(OK, b"fine".to_vec()).unwrap(), b"fine");
}
