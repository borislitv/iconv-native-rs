use iconv_native::stream::{Converter, Progress, Status};

#[test]
fn converts_into_only_the_supplied_output() {
    let mut converter = Converter::new(c"ISO-8859-1", c"UTF-8").unwrap();
    let mut output = [0xcc; 8];
    assert_eq!(
        converter.convert(b"caf\xe9", &mut output),
        Progress {
            consumed: 4,
            written: 5,
            status: Status::Complete,
        }
    );
    assert_eq!(&output[..5], "café".as_bytes());
    assert_eq!(&output[5..], &[0xcc; 3]);
}

#[test]
fn output_full_reports_the_unconsumed_suffix_for_retry() {
    let mut converter = Converter::new(c"ISO-8859-1", c"UTF-8").unwrap();
    let mut first = [0; 1];
    assert_eq!(
        converter.convert(b"a\xe9", &mut first),
        Progress {
            consumed: 1,
            written: 1,
            status: Status::OutputFull,
        }
    );
    assert_eq!(first, *b"a");
    let mut second = [0; 2];
    assert_eq!(
        converter.convert(b"\xe9", &mut second),
        Progress {
            consumed: 1,
            written: 2,
            status: Status::Complete,
        }
    );
    assert_eq!(&second, "é".as_bytes());
}

#[test]
fn incomplete_input_is_retained_and_retried_with_more_bytes() {
    let mut converter = Converter::new(c"UTF-8", c"UTF-16LE").unwrap();
    let mut output = [0xcc; 4];
    assert_eq!(
        converter.convert(&[0xe3, 0x81], &mut output),
        Progress {
            consumed: 0,
            written: 0,
            status: Status::Incomplete,
        }
    );
    assert_eq!(output, [0xcc; 4]);
    assert_eq!(
        converter.convert("あ".as_bytes(), &mut output),
        Progress {
            consumed: 3,
            written: 2,
            status: Status::Complete,
        }
    );
    assert_eq!(output, [0x42, 0x30, 0xcc, 0xcc]);
}

#[test]
fn malformed_input_and_unknown_encoding_are_not_success() {
    assert!(Converter::new(c"synthetic-unknown-encoding", c"UTF-8").is_none());
    let mut converter = Converter::new(c"UTF-8", c"UTF-16LE").unwrap();
    let mut output = [0xcc; 4];
    assert_eq!(
        converter.convert(&[0xff], &mut output),
        Progress {
            consumed: 0,
            written: 0,
            status: Status::Invalid,
        }
    );
    assert_eq!(output, [0xcc; 4]);
}

#[test]
fn stateful_flush_retries_and_resets_without_losing_output() {
    let mut converter = Converter::new(c"UTF-8", c"ISO-2022-JP").unwrap();
    let mut output = [0; 8];
    let progress = converter.convert("あ".as_bytes(), &mut output);
    assert_eq!(
        progress,
        Progress {
            consumed: 3,
            written: 5,
            status: Status::Complete
        }
    );
    assert_eq!(&output[..5], b"\x1b$B$\"");
    assert_eq!(
        converter.flush(&mut []),
        Progress {
            consumed: 0,
            written: 0,
            status: Status::OutputFull,
        }
    );
    assert_eq!(
        converter.flush(&mut output),
        Progress {
            consumed: 0,
            written: 3,
            status: Status::Complete,
        }
    );
    assert_eq!(&output[..3], b"\x1b(B");
    assert_eq!(
        converter.convert(b"A", &mut output),
        Progress {
            consumed: 1,
            written: 1,
            status: Status::Complete,
        }
    );
    assert_eq!(output[0], b'A');
}

#[test]
fn empty_input_does_not_flush_pending_tscii_state() {
    let mut converter = Converter::new(c"TSCII", c"UTF-8").unwrap();
    let mut output = [0; 16];
    let progress = converter.convert(&[0x8a], &mut output);
    assert_eq!(progress.status, Status::Complete);
    assert_eq!(progress.consumed, 1);
    let empty = converter.convert(&[], &mut output);
    assert_eq!(
        empty,
        Progress {
            consumed: 0,
            written: 0,
            status: Status::Complete
        }
    );
    let flushed = converter.flush(&mut output);
    assert_eq!(
        flushed,
        Progress {
            consumed: 0,
            written: 3,
            status: Status::Complete
        }
    );
    assert_eq!(&output[..3], "்".as_bytes());
}
