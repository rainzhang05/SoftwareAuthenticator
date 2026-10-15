//! Bounded public COSE mutations applied to otherwise valid exchanges.
use crate::cbor::{bytes, int, text};
use ciborium::value::Value;

pub(crate) const CASE_COUNT: u8 = 31;

/// Return the changed map and the independent engine-side acceptance oracle.
pub(crate) fn mutate(key: Value, case: u8) -> (Value, bool) {
    let Value::Map(mut entries) = key else {
        panic!("fixture COSE map")
    };
    let case = case % CASE_COUNT;
    let change = match case {
        0 => return (Value::Map(entries), true),
        1 => (3, Some(int(-7))),
        2 => {
            entries.extend([(int(2), bytes(&[1])), (int(99), Value::Bool(false))]);
            return (Value::Map(entries), true);
        }
        3..=14 => {
            let label = [1, 3, -1][usize::from((case - 3) / 4)];
            let value = match (case - 3) % 4 {
                0 => None,
                1 => Some(Value::Bool(true)),
                2 => Some(text("unexpected")),
                _ => Some(int(match label {
                    1 => 1,
                    3 => -26,
                    _ => 2,
                })),
            };
            (label, value)
        }
        15..=26 => {
            let label = [-2, -3][usize::from((case - 15) / 6)];
            let value = match (case - 15) % 6 {
                0 => None,
                1 => Some(Value::Bool(true)),
                2 => Some(text("unexpected")),
                3 => Some(int(0)),
                4 => Some(bytes(&[0; 31])),
                _ => Some(bytes(&[0; 33])),
            };
            (label, value)
        }
        27 => {
            for (label, value) in &mut entries {
                if *label == int(-2) || *label == int(-3) {
                    *value = bytes(&[0; 32]);
                }
            }
            return (Value::Map(entries), false);
        }
        _ => (3, Some(int([0, -257, i64::MAX][usize::from(case - 28)]))),
    };
    entries.retain(|(key, _)| *key != int(change.0));
    entries.extend(change.1.map(|value| (int(change.0), value)));
    (Value::Map(entries), case == 1)
}
