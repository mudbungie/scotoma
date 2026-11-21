//! What crosses the socket between a client and the resident process.
//!
//! A frame is `tag (1 byte) | length (4 bytes, big-endian) | body`. A
//! conversation is one request frame, then replies; stream operations
//! alternate one chunk each way. A request body is a packed list of fields.

use crate::Error;
use std::io::{self, Read, Write};

/// The request: a packed field list `[actor, grant token, op, args...]`.
pub(crate) const ASK: u8 = b'?';
/// A successful reply, or a chunk of an input stream.
pub(crate) const OK: u8 = b'.';
/// The end of an input stream.
pub(crate) const END: u8 = b'$';
/// A chunk of a running command's stdout / stderr.
/// A piece of the caller's input, for a command.
pub(crate) const IN: u8 = b'0';
pub(crate) const OUT: u8 = b'1';
pub(crate) const ERR: u8 = b'2';

/// No frame is larger than this; a longer length is a broken peer.
pub(crate) const LIMIT: usize = 1 << 24;

pub(crate) fn send(mut to: impl Write, tag: u8, body: &[u8]) -> io::Result<()> {
    let length = u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes();
    to.write_all(&[&[tag], length.as_slice(), body].concat())
}

pub(crate) fn recv(mut from: impl Read) -> io::Result<(u8, Vec<u8>)> {
    let mut head = [0; 5];
    from.read_exact(&mut head)?;
    let [tag, length @ ..] = head;
    let length = u32::from_be_bytes(length) as usize;
    if length > LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut body = vec![0; length];
    from.read_exact(&mut body)?;
    Ok((tag, body))
}

/// A list of byte strings as one body: each is `length (4 bytes) | bytes`.
pub(crate) fn pack(fields: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for field in fields {
        let _ = send(&mut body, 0, field);
    }
    body
}

/// The inverse of [`pack`]; `None` if the body is not a packed list.
pub(crate) fn unpack(mut body: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut fields = Vec::new();
    while !body.is_empty() {
        fields.push(recv(&mut body).ok()?.1);
    }
    Some(fields)
}

/// An error as a reply frame. The tag is the variant; only names and
/// reasons travel, as everywhere else.
pub(crate) fn refusal(error: &Error) -> (u8, String) {
    match error {
        Error::Name(name) => (b'N', name.clone()),
        Error::Unknown(name) => (b'U', name.clone()),
        Error::Empty => (b'E', String::new()),
        Error::Leak(name) => (b'L', name.clone()),
        Error::Denied(why) => (b'D', why.clone()),
        Error::Sealed => (b'S', String::new()),
        Error::Locked => (b'K', String::new()),
        Error::Password => (b'P', String::new()),
        Error::Io { .. } => (b'I', error.to_string()),
    }
}

/// A reply frame as the result it stands for.
pub(crate) fn outcome(tag: u8, body: Vec<u8>) -> Result<Vec<u8>, Error> {
    if tag == OK {
        return Ok(body);
    }
    let text = String::from_utf8_lossy(&body).into_owned();
    Err(match tag {
        b'N' => Error::Name(text),
        b'U' => Error::Unknown(text),
        b'E' => Error::Empty,
        b'L' => Error::Leak(text),
        b'D' => Error::Denied(text),
        b'S' => Error::Sealed,
        b'K' => Error::Locked,
        b'P' => Error::Password,
        _ => Error::Io {
            context: "resident".to_owned(),
            source: io::Error::other(text),
        },
    })
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;
