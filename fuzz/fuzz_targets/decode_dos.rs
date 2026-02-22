#![no_main]

use std::collections::BTreeMap;

use frankenengine_engine::deterministic_serde::{
    CanonicalValue, SchemaRegistry, deserialize_with_schema, decode_value, encode_value,
    serialize_with_schema,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let _ = decode_value(data);

    if data.len() >= 32 {
        let mut schema_bytes = [0u8; 32];
        schema_bytes.copy_from_slice(&data[..32]);
        let schema = frankenengine_engine::deterministic_serde::SchemaHash(schema_bytes);
        let _ = deserialize_with_schema(&schema, data);
    }

    let synthetic = synthetic_value(data);
    let mut registry = SchemaRegistry::new();
    let schema = registry.register("fuzz.decode_dos", 1, b"fuzz.decode_dos.schema.v1");
    let encoded = serialize_with_schema(&schema, &synthetic);
    let _ = registry.deserialize_checked(&encoded);

    if let Ok(round_trip) = decode_value(&encode_value(&synthetic)) {
        let _ = encode_value(&round_trip);
    }
});

fn synthetic_value(data: &[u8]) -> CanonicalValue {
    match byte(data, 0) % 5 {
        0 => CanonicalValue::U64(u64::from(byte(data, 1))),
        1 => CanonicalValue::Bytes(data.iter().copied().take(128).collect()),
        2 => CanonicalValue::String(ascii_string(data, 64)),
        3 => CanonicalValue::Array(
            data.iter()
                .copied()
                .take(16)
                .map(|item| CanonicalValue::U64(u64::from(item)))
                .collect(),
        ),
        _ => {
            let mut map = BTreeMap::new();
            for (index, value) in data.iter().copied().take(12).enumerate() {
                map.insert(format!("k{index:02x}"), CanonicalValue::U64(u64::from(value)));
            }
            CanonicalValue::Map(map)
        }
    }
}

fn ascii_string(data: &[u8], max_len: usize) -> String {
    data.iter()
        .copied()
        .take(max_len)
        .map(|byte| char::from(b'a' + (byte % 26)))
        .collect()
}

fn byte(data: &[u8], index: usize) -> u8 {
    if data.is_empty() {
        return 0;
    }
    data[index % data.len()]
}
