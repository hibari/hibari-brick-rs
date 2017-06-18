// ----------------------------------------------------------------------
//  Copyright (c) 2016-2017 Hibari developers. All rights reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
// ----------------------------------------------------------------------

use blake2_rfc::blake2b::{blake2b, Blake2b};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

// use std::io;
// use std::io::prelude::*;
use std::io::{Cursor, Write};

// (@TODO Add BrickName in the super block or trailer block?)
//
// ubint: unsigned, big-endian, integer
//
// Log File Layout
// - Superblock
//   * Signature     (8 bytes)                   <<16#8A, "HLG", "\r", "\n", 16#1A, "\n">>
//   * Version       (2 bytes, ubint)            <<0, 1>>
//   * Reserved      (6 bytes)                   <<"Hibari">>
// - Hunk 1
//   * Header        (wal: 12 bytes, blob store: 8 or 10 bytes)
//   * Body          (variable length)
//   * Footer        (variable length)
//     ** ...
//     ** Padding    (variable length)           Next Hunk should be aligned to 8 byte boundary
// - Hunk 2
//   * ...
// - ...
// - Hunk N
//   * ...
// - Trailer block
//   * Magic         (4 bytes)
//   * Hunk Overhead (4 bytes)                   The sum of the sizes of headers and
//                                               footers of all hunks.
//
// ubint: unsigned, big-endian, integer
//
// Hunk Layout - Header for all blob types
// - Header (12 bytes, fixed length)
//   * Header Magic Numbers (2 bytes)                    <<16#90, 16#7F>>  %% no meaning
//   * Type (1 byte)
//   * Flags (has_checksum, etc.) (1 byte)
//   * BrickNameSize (2 bytes, ubint)                    0 for non-WAL hunks
//   * NumberOfBlobs (2 bytes, ubnit)
//   * TotalBlobSize (4 bytes, ubnit)                    Max value size is (4 GB - 1 byte)
//
//
// Hunk Layout - metadata; many blobs in one hunk (OBSOLETE)
// - Header (12 bytes, fixed length, see above for details)
// - Body (variable length)
//   * BrickName (binary)
//   * Blob1 (binary)
//   * Blob2 (binary)
//   * ...
//   * BlobN (binary)
// - Footer (variable length)
//   * Footer Magic Number (2 bytes)                    <<16#07, 16#E3>>  %% no meaning
//   * Blob Checksum (32 bytes) (optional)
//   * BrickName (binary)
//   * Blob Index (4 bytes * NumberOfBlobs, ubint)
//   * Padding                                          Total hunk size is aligned to 8 byte boundary
//
//
// Hunk Layout - blob_wal; many blobs in one hunk
// - Header (12 bytes, fixed length, see above for details)
// - Body (variable length)
//   * Blob1 (binary)
//   * Blob2 (binary)
//   * ...
//   * BlobN (binary)
// - Footer (variable length)
//   * Footer Magic Number (2 bytes)                    <<16#07, 16#E3>>  %% no meaning
//   * Blob Checksum (32 bytes) (optional)
//   * BrickName (binary)
//   * Blob Index (4 bytes * NumberOfBlobs, ubint)
//   * Padding                                          Total hunk size is aligned to 8 byte boundary
//
//
// Hunk Layout - blob_single; one blob in one hunk
// - Header (12 bytes, fixed length, see above for details)
// - Body (variable length)
//   * Blob (binary)
// - Footer (variable length)
//   * Footer Magic Number (2 bytes)                    <<16#07, 16#E3>>  %% no meaning
//   * Blob Checksum (32 bytes) (optional)
//   * Blob Age (1 byte)
//   * Padding                                          Total hunk size is aligned to 8 byte boundary
//
//
// Hunk Layout - blob_multi; many blobs in one hunk
// - Header (12 bytes, fixed length, see above for details)
// - Body (variable length)
//   * Blob1 (binary)
//   * Blob2 (binary)
//   * ...
//   * BlobN (binary)
// - Footer (variable length)
//   * Footer Magic Number (2 bytes)                    <<16#07, 16#E3>>  %% no meaning
//   * Blob Checksum (32 bytes) (optional)
//   * Blob Index (4 bytes * NumberOfBlobs, ubint)
//   * Blob Ages  (1 byte * NumberOfBlobs, ubint))
//   * Padding                                          Total hunk size is aligned to 8 byte boundary


// Need fixed-length types for better space utilization? Perhaps
// smaller blob (< 16 bytes or so) might be embedded into its metadata
// (= value_in_ram).
//
// For a small blob, an upper layer (write-back and scavenge
// processes) should pack multiple values into one hunk (~= 4KB
// so that it can avoid the overhead of hunk enclosure.

// const FILE_SIGNATURE: &'static [u8] = &[0x8Au8, 'H' as u8, 'L' as u8, 'G' as u8, '\r' as u8,
//                                         '\n' as u8, 0x1Au8, '\n' as u8];

const HUNK_HEADER_SIZE: u8 = 12;
const HUNK_MIN_FOOTER_SIZE: u8 = 2;
const HUNK_ALIGNMENT: u8 = 8;

const HUNK_HEADER_MAGIC: &'static [u8] = &[0x90u8, 0x7Fu8];  // 144, 127
const HUNK_FOOTER_MAGIC: &'static [u8] = &[0x07u8, 0xE3u8];  //   7, 227

const TYPE_METADATA: u8 = b'm';
const TYPE_BLOB_WAL: u8 = b'w';
const TYPE_BLOB_SINGLE: u8 = b's';
const TYPE_BLOB_MULTI: u8 = b'p';  // "p" stands for "packed" blobs. ("m" is already taken)

// Flags are stored in 1 byte space, so we can put up to 8 flags.
const FLAG_NO_CHECKSUM: u8 = 0b_0000_0001;

// Blake2b with digest length of 256 bits
pub const CHECKSUM_LEN: usize = 32;

type RawDigest = [u8; CHECKSUM_LEN];

#[derive(Debug)]
pub enum BoxedHunk {
    Metadata, // Not in-use
    BlobWal(BlobWalHunk),
    BlobSingle(BlobSingleHunk),
    BlobMulti(BlobMultiHunk),
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum HunkType {
    Metadata, // Not in-use
    BlobWal,
    BlobSingle,
    BlobMulti,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum HunkFlag {
    NoChecksum,
}

pub trait Hunk {
    // converts Hunk into BinaryHunk (self will be cunsumed.)
    fn encode(self) -> BinaryHunk;
}

#[derive(PartialEq, Debug)]
pub struct Blob(pub Vec<u8>);

#[derive(Debug)]
pub struct ParseError; // TODO

#[derive(PartialEq, Debug)]
pub struct BlobWalHunk {
    hunk_type: HunkType,
    brick_name: String,
    flags: Vec<HunkFlag>,
    blobs: Vec<Blob>,
    pub checksum: Option<RawDigest>,
}

#[derive(PartialEq, Debug)]
pub struct BlobSingleHunk {
    hunk_type: HunkType,
    flags: Vec<HunkFlag>,
    blob: Blob,
    age: u8,
    checksum: Option<RawDigest>,
}

#[derive(PartialEq, Debug)]
pub struct BlobMultiHunk {
    hunk_type: HunkType,
    flags: Vec<HunkFlag>,
    blobs: Vec<Blob>,
    ages: Vec<u8>,
    checksum: Option<RawDigest>,
}

#[derive(Debug)]
pub struct HunkSize {
    pub raw_size: u32,
    pub footer_size: u16,
    pub padding_size: u8,
    pub overhead: u8,
}

#[derive(Debug)]
pub struct BinaryHunk {
    pub hunk: Vec<u8>,
    pub hunk_size: u32,
    pub overhead: u8,
    pub blob_index: Vec<u32>,
}

impl BlobWalHunk {
    pub fn new(brick_name: &str, blobs: Vec<Blob>, flags: &[HunkFlag]) -> Self {
        let checksum = calc_checksum_of_blobs(&blobs, flags);
        BlobWalHunk {
            hunk_type: HunkType::BlobWal,
            brick_name: brick_name.to_string(),
            flags: clone_flags(flags),
            blobs: blobs,
            checksum: checksum,
        }
    }

    pub fn new_with_checksum(brick_name: &str,
                             blobs: Vec<Blob>,
                             flags: Vec<HunkFlag>,
                             checksum: Option<RawDigest>)
                             -> Self {
        BlobWalHunk {
            hunk_type: HunkType::BlobWal,
            brick_name: brick_name.to_string(),
            flags: flags,
            blobs: blobs,
            checksum: checksum,
        }
    }
}

impl Hunk for BlobWalHunk {
    fn encode(self) -> BinaryHunk {
        let BlobWalHunk { hunk_type, flags, brick_name, blobs, checksum } = self;
        encode_hunk(hunk_type, &flags[..], Some(brick_name), blobs, &None, checksum)
    }
}

impl BlobSingleHunk {
    pub fn new(blob: Blob, flags: &[HunkFlag]) -> Self {
        let checksum = calc_checksum_of_blob(&blob, flags);
        BlobSingleHunk {
            hunk_type: HunkType::BlobSingle,
            flags: clone_flags(flags),
            blob: blob,
            age: 0,
            checksum: checksum,
        }
    }

    pub fn new_with_age_and_checksum(blob: Blob,
                                     flags: Vec<HunkFlag>,
                                     age: u8,
                                     checksum: Option<RawDigest>)
                                     -> Self {
        BlobSingleHunk {
            hunk_type: HunkType::BlobSingle,
            flags: flags,
            blob: blob,
            age: age,
            checksum: checksum,
        }
    }
}

impl Hunk for BlobSingleHunk {
    fn encode(self) -> BinaryHunk {
        let BlobSingleHunk { hunk_type, flags, blob, age, checksum } = self;
        let blobs = vec![blob];
        let ages = vec![age];
        encode_hunk(hunk_type, &flags[..], None, blobs, &Some(ages), checksum)
    }
}

impl BlobMultiHunk {
    pub fn new(blobs: Vec<Blob>, flags: &[HunkFlag]) -> Self {
        let checksum = calc_checksum_of_blobs(&blobs, flags);
        let ages = vec![0; blobs.len()];
        BlobMultiHunk {
            hunk_type: HunkType::BlobMulti,
            flags: clone_flags(flags),
            blobs: blobs,
            ages: ages,
            checksum: checksum,
        }
    }

    pub fn new_with_ages_and_checksum(blobs: Vec<Blob>,
                                      flags: Vec<HunkFlag>,
                                      ages: &[u8],
                                      checksum: Option<RawDigest>)
                                      -> Self {
        BlobMultiHunk {
            hunk_type: HunkType::BlobMulti,
            flags: flags,
            blobs: blobs,
            ages: create_vec_u8_from_slice(ages),
            checksum: checksum,
        }
    }
}

impl Hunk for BlobMultiHunk {
    fn encode(self) -> BinaryHunk {
        let BlobMultiHunk { hunk_type, flags, blobs, ages, checksum } = self;
        encode_hunk(hunk_type, &flags[..], None, blobs, &Some(ages), checksum)
    }
}

pub fn calc_hunk_size(hunk_type: &HunkType,
                      hunk_flags: &[HunkFlag],
                      brick_name_size: u16,
                      number_of_blobs: u16,
                      total_blob_size: u32)
                      -> HunkSize {
    let checksum_size: u16 = if has_checksum(hunk_flags) { CHECKSUM_LEN as u16 } else { 0 };
    let blob_index_size: u16 = if *hunk_type == HunkType::BlobSingle {
        0
    } else {
        4 * number_of_blobs
    };
    let blob_age_size: u16 = if *hunk_type == HunkType::BlobSingle ||
                                *hunk_type == HunkType::BlobMulti {
        number_of_blobs
    } else {
        0
    };

    let footer_size = HUNK_MIN_FOOTER_SIZE as u16 + checksum_size + brick_name_size + blob_index_size +
                      blob_age_size;
    // raw_size includes footer_size.
    let raw_size = HUNK_HEADER_SIZE as u32 + total_blob_size + footer_size as u32;
    let rem: u8 = (raw_size % HUNK_ALIGNMENT as u32) as u8;
    let padding_size: u8 = if rem == 0 { 0 } else { HUNK_ALIGNMENT - rem };
    let overhead = (raw_size + padding_size as u32 - total_blob_size) as u8;
    HunkSize {
        raw_size: raw_size,
        footer_size: footer_size,
        padding_size: padding_size,
        overhead: overhead,
    }
}

fn encode_hunk(hunk_type: HunkType,
               flags: &[HunkFlag],
               brick_name: Option<String>,
               blobs: Vec<Blob>,
               blob_ages: &Option<Vec<u8>>,
               checksum: Option<RawDigest>)
               -> BinaryHunk {
    let (encoded_brick_name, brick_name_size) = encode_brick_name(brick_name);
    if checksum.is_none() {
        assert!(!has_checksum(flags))
    }
    let (blob_index, number_of_blobs) = create_blob_index(&blobs);
    let total_blob_size = total_blob_size(&blobs);
    let HunkSize { raw_size, padding_size, overhead, .. } = calc_hunk_size(&hunk_type,
                                                                           flags,
                                                                           brick_name_size,
                                                                           number_of_blobs,
                                                                           total_blob_size);
    let hunk_size = raw_size + padding_size as u32;
    let mut hunk = Vec::with_capacity(hunk_size as usize);

    append_hunk_header(&mut hunk,
                       &hunk_type,
                       flags,
                       brick_name_size,
                       number_of_blobs,
                       total_blob_size);
    append_blobs(&mut hunk, blobs);
    append_hunk_footer(&mut hunk,
                       &hunk_type,
                       checksum,
                       encoded_brick_name,
                       blob_ages,
                       &blob_index,
                       padding_size);

    BinaryHunk {
        hunk: hunk,
        hunk_size: hunk_size,
        overhead: overhead,
        blob_index: blob_index,
    }
}

fn create_blob_index(blobs: &[Blob]) -> (Vec<u32>, u16) {
    let blob_count = blobs.len();
    let mut blob_index = Vec::with_capacity(blob_count);

    if blob_count > 0 {
        let mut offset = HUNK_HEADER_SIZE as u32;
        blob_index.push(offset);

        for &Blob(ref blob) in &blobs[..(blob_count - 1)] {
            offset += blob.len() as u32;
            blob_index.push(offset);
        }
    }
    (blob_index, blob_count as u16)
}

fn append_hunk_header(mut hunk: &mut Vec<u8>,
                      hunk_type: &HunkType,
                      flags: &[HunkFlag],
                      brick_name_size: u16,
                      number_of_blobs: u16,
                      total_blob_size: u32) {
    hunk.extend_from_slice(HUNK_HEADER_MAGIC);
    append_encoded_type(&mut hunk, hunk_type);
    append_encoded_flags(&mut hunk, flags);
    hunk.write_u16::<BigEndian>(brick_name_size).unwrap();
    hunk.write_u16::<BigEndian>(number_of_blobs).unwrap();
    hunk.write_u32::<BigEndian>(total_blob_size).unwrap();
}

// Consumes blobs
fn append_blobs(hunk: &mut Vec<u8>, blobs: Vec<Blob>) {
    for Blob(mut blob) in blobs {
        hunk.append(&mut blob);
    }
}

fn append_hunk_footer(hunk: &mut Vec<u8>,
                      hunk_type: &HunkType,
                      checksum: Option<RawDigest>,
                      encoded_brick_name: Option<Vec<u8>>,
                      blob_ages: &Option<Vec<u8>>,
                      blob_index: &[u32],
                      padding_size: u8) {
    hunk.extend_from_slice(HUNK_FOOTER_MAGIC);

    if let Some(checksum) = checksum {
        hunk.write_all(&checksum).unwrap();
    }
    if *hunk_type == HunkType::Metadata || *hunk_type == HunkType::BlobWal {
        if let Some(mut bn) = encoded_brick_name {
            hunk.append(&mut bn)
        }
    }
    if *hunk_type != HunkType::BlobSingle {
        for offset in blob_index {
            hunk.write_u32::<BigEndian>(*offset).unwrap();
        }
    }
    if *hunk_type == HunkType::BlobSingle || *hunk_type == HunkType::BlobMulti {
        if let Some(ref ages) = *blob_ages {
            for age in ages {
                hunk.push(*age);
            }
        } else {
            panic!("no age provided");
        }
    }
    let new_len = hunk.len() + padding_size as usize;
    hunk.resize(new_len, 0);
}

fn clone_flags(flags: &[HunkFlag]) -> Vec<HunkFlag> {
    let mut flags_vec = Vec::with_capacity(flags.len());
    flags_vec.extend_from_slice(flags);
    flags_vec
}

fn has_checksum(flags: &[HunkFlag]) -> bool {
    !flags.contains(&HunkFlag::NoChecksum)
}

fn calc_checksum_of_blob(blob: &Blob, flags: &[HunkFlag]) -> Option<RawDigest> {
    if has_checksum(flags) {
        let Blob(ref blob) = *blob;
        let digest = blake2b(CHECKSUM_LEN, &[], blob);
        let mut result = [0u8; CHECKSUM_LEN];
        result.copy_from_slice(digest.as_bytes());
        Some(result)
    } else {
        None
    }
}

pub fn calc_checksum_of_blobs(blobs: &[Blob], flags: &[HunkFlag]) -> Option<RawDigest> {
    if has_checksum(flags) {
        let mut hasher = Blake2b::new(CHECKSUM_LEN);
        for &Blob(ref blob) in blobs {
            hasher.update(blob);
        }
        let digest = hasher.finalize();
        let mut result = [0u8; CHECKSUM_LEN];
        result.copy_from_slice(digest.as_bytes());
        Some(result)
    } else {
        None
    }
}

fn append_encoded_type(hunk: &mut Vec<u8>, hunk_type: &HunkType) {
    match *hunk_type {
        HunkType::Metadata => hunk.push(TYPE_METADATA),
        HunkType::BlobWal => hunk.push(TYPE_BLOB_WAL),
        HunkType::BlobSingle => hunk.push(TYPE_BLOB_SINGLE),
        HunkType::BlobMulti => hunk.push(TYPE_BLOB_MULTI),
    }
}

fn append_encoded_flags(hunk: &mut Vec<u8>, flags: &[HunkFlag]) {
    let mut encoded_flags = 0x00u8;
    for flag in flags {
        match *flag {
            HunkFlag::NoChecksum => encoded_flags |= FLAG_NO_CHECKSUM,
        }
    }
    hunk.push(encoded_flags);
}

fn encode_brick_name(brick_name: Option<String>) -> (Option<Vec<u8>>, u16) {
    if let Some(brick_name) = brick_name {
        let encoded = brick_name.into_bytes();
        let len = encoded.len() as u16;
        (Some(encoded), len)
    } else {
        (None, 0)
    }
}

fn total_blob_size(blobs: &[Blob]) -> u32 {
    blobs.iter().fold(0, |acc, &Blob(ref blob)| acc + blob.len()) as u32
}

pub fn decode_hunks(bin: &[u8], start_offset: usize) -> Result<(Vec<BoxedHunk>, usize), (ParseError, usize)> {
    let mut hunks = Vec::new();
    let mut offset = start_offset;
    while offset < bin.len() {
        match decode_hunk(bin, offset) {
            Ok((hunk, next_offset)) => {
                // debug!("decode_hunks: decoded hunk at {}. next offset: {}", offset, next_offset);
                hunks.push(hunk);
                offset = next_offset;
            }
            Err((ParseError, _)) => break,
        }
    }
    Ok((hunks, offset))
}

fn decode_hunk(bin: &[u8], offset: usize) -> Result<(BoxedHunk, usize), (ParseError, usize)> {
    let header_size = HUNK_HEADER_SIZE as usize;
    let bin = &bin[offset..];

    if bin.len() < header_size || !bin.starts_with(HUNK_HEADER_MAGIC) {
        return Err((ParseError, offset));
    }

    let (hunk_type, flags, brick_name_size, number_of_blobs, total_blob_size) =
        decode_header(&bin[..header_size]).unwrap();

    let HunkSize { footer_size, padding_size, .. } = calc_hunk_size(&hunk_type,
                                                                    &flags,
                                                                    brick_name_size,
                                                                    number_of_blobs,
                                                                    total_blob_size);

    let footer_start = header_size + total_blob_size as usize;
    let footer_end = footer_start + footer_size as usize + padding_size as usize;
    let new_offset = offset + footer_end;
    if bin.len() < footer_end {
        debug!("bin.len: {}, footer_end: {}", bin.len(), footer_end);
        return Err((ParseError, offset));
    }

    let body_slice = &bin[header_size..footer_start];
    let footer_slice = &bin[footer_start..footer_end];

    let ParseHunkFooterResult { checksum, brick_name, blob_index_range, blob_ages_range } =
        parse_hunk_footer(&hunk_type,
                          has_checksum(&flags),
                          brick_name_size,
                          number_of_blobs,
                          footer_slice)
            .unwrap();
    let blob_index_slice = &footer_slice[blob_index_range.0..blob_index_range.1];

    let hunk = match hunk_type {
        HunkType::Metadata => unimplemented!(),
        HunkType::BlobWal => {
            let blobs = parse_hunk_body(body_slice, blob_index_slice, number_of_blobs).unwrap();
            BoxedHunk::BlobWal(BlobWalHunk::new_with_checksum(&brick_name.unwrap(), blobs, flags, checksum))
        }
        HunkType::BlobSingle => {
            let blob = create_vec_u8_from_slice(body_slice);
            let blob_ages_range = blob_ages_range.unwrap();
            assert_eq!(1, blob_ages_range.1 - blob_ages_range.0);
            BoxedHunk::BlobSingle(BlobSingleHunk::new_with_age_and_checksum(Blob(blob),
                                                                            flags,
                                                                            footer_slice[blob_ages_range.0],
                                                                            checksum))
        }
        HunkType::BlobMulti => {
            let blobs = parse_hunk_body(body_slice, blob_index_slice, number_of_blobs).unwrap();
            let blob_ages_range = blob_ages_range.unwrap();
            let blob_ages_slice = &footer_slice[blob_ages_range.0..blob_ages_range.1];
            BoxedHunk::BlobMulti(BlobMultiHunk::new_with_ages_and_checksum(blobs,
                                                                           flags,
                                                                           blob_ages_slice,
                                                                           checksum))
        }
    };

    Ok((hunk, new_offset))
}

fn decode_header(header: &[u8]) -> Result<(HunkType, Vec<HunkFlag>, u16, u16, u32), ParseError> {
    let mut reader = Cursor::new(&header[2..]);
    let hunk_type = reader.read_u8().unwrap();
    let flags = reader.read_u8().unwrap();
    let brick_name_size = reader.read_u16::<BigEndian>().unwrap();
    let number_of_blobs = reader.read_u16::<BigEndian>().unwrap();
    let total_blob_size = reader.read_u32::<BigEndian>().unwrap();

    let decoded_type = decode_type(hunk_type)?;
    let decoded_flags = decode_flags(flags)?;

    Ok((decoded_type, decoded_flags, brick_name_size, number_of_blobs, total_blob_size))
}

fn parse_hunk_body(blob_slice: &[u8],
                   blob_index_bin: &[u8],
                   number_of_blobs: u16)
                   -> Result<Vec<Blob>, ParseError> {
    if blob_index_bin.len() / 4 != number_of_blobs as usize {
        return Err(ParseError);
    }

    let mut blobs = Vec::with_capacity(number_of_blobs as usize);
    let header_size = HUNK_HEADER_SIZE as usize;
    let mut start_offset = 0;

    if number_of_blobs > 1 {
        let mut index_reader = Cursor::new(&blob_index_bin[4..]);
        let mut end_offset;

        for _ in 0..(number_of_blobs - 1) {
            end_offset = index_reader.read_u32::<BigEndian>().unwrap() as usize - header_size;
            let blob = create_vec_u8_from_slice(&blob_slice[start_offset..end_offset]);
            blobs.push(Blob(blob));
            start_offset = end_offset;
        }

    }

    let blob = create_vec_u8_from_slice(&blob_slice[start_offset..]);
    blobs.push(Blob(blob));

    Ok(blobs)
}

struct ParseHunkFooterResult {
    checksum: Option<RawDigest>,
    brick_name: Option<String>,
    blob_index_range: (usize, usize),
    blob_ages_range: Option<(usize, usize)>,
}

fn parse_hunk_footer(hunk_type: &HunkType,
                     has_checksum: bool,
                     brick_name_size: u16,
                     number_of_blobs: u16,
                     footer_slice: &[u8])
                     -> Result<ParseHunkFooterResult, ParseError> {
    if !footer_slice.starts_with(HUNK_FOOTER_MAGIC) {
        return Err(ParseError);
    }

    let mut offset = HUNK_FOOTER_MAGIC.len();

    let checksum;
    if has_checksum {
        let end_offset = offset + CHECKSUM_LEN as usize;
        let mut result = [0u8; CHECKSUM_LEN];
        result.copy_from_slice(&footer_slice[offset..end_offset]);
        checksum = Some(result);
        offset = end_offset;
    } else {
        checksum = None;
    }

    let brick_name;
    if *hunk_type == HunkType::Metadata || *hunk_type == HunkType::BlobWal {
        let end_offset = offset + brick_name_size as usize;
        brick_name = Some(decode_brick_name(&footer_slice[offset..end_offset]).unwrap());
        offset = end_offset;
    } else {
        brick_name = None;
    }

    let blob_index_start = offset;
    offset += 4 * number_of_blobs as usize;
    let blob_index_range = (blob_index_start, offset);

    let blob_ages_range;
    if *hunk_type == HunkType::BlobSingle || *hunk_type == HunkType::BlobMulti {
        let blob_ages_start = offset;
        offset += number_of_blobs as usize;
        blob_ages_range = Some((blob_ages_start, offset));
    } else {
        blob_ages_range = None
    }

    Ok(ParseHunkFooterResult {
        checksum: checksum,
        brick_name: brick_name,
        blob_index_range: blob_index_range,
        blob_ages_range: blob_ages_range,
    })
}

fn decode_type(hunk_type: u8) -> Result<HunkType, ParseError> {
    match hunk_type {
        TYPE_METADATA => Ok(HunkType::Metadata),
        TYPE_BLOB_WAL => Ok(HunkType::BlobWal),
        TYPE_BLOB_SINGLE => Ok(HunkType::BlobSingle),
        TYPE_BLOB_MULTI => Ok(HunkType::BlobMulti),
        _ => Err(ParseError),
    }
}

fn decode_flags(flags: u8) -> Result<Vec<HunkFlag>, ParseError> {
    let mut decoded_flags = Vec::new();
    if flags & FLAG_NO_CHECKSUM != 0 {
        decoded_flags.push(HunkFlag::NoChecksum);
    }
    Ok(decoded_flags)
}

fn decode_brick_name(bin: &[u8]) -> Result<String, ParseError> {
    if bin.is_empty() {
        Ok("".to_string())
    } else {
        let v = create_vec_u8_from_slice(bin);
        String::from_utf8(v).map_err(|_e| ParseError)
    }
}

fn create_vec_u8_from_slice(bin: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(bin.len());
    v.extend_from_slice(bin);
    v
}

// ---------------------------------------------------------------------------


#[cfg(test)]
mod tests {
    extern crate env_logger;

    use super::{calc_hunk_size, decode_hunks, BinaryHunk, Blob, BlobWalHunk, BlobSingleHunk,
                BlobMultiHunk, BoxedHunk, Hunk, HunkFlag, HunkSize, HunkType, ParseError};

    // Blake2s checksum can be generated by:
    //   python3 -c "import hashlib; print(hashlib.blake2b(b'Hello, world!', digest_size=32).hexdigest())"

    #[test]
    fn test_encode_hunks() {
        let _ = env_logger::init();

        let brick_name = "brick1";
        let blob1_src = b"Hello";
        let blob2_src = b", ";
        let blob3_src = b"world!";
        let hunk_flags = [];
        let hunk_flags_no_checksum = [HunkFlag::NoChecksum];

        {
            // Zero-byte blob. NOTE: Hibari will not create blob at all for this case.
            let blobs = Vec::new();
            let hunk = BlobWalHunk::new(brick_name, blobs, &hunk_flags_no_checksum);
            let _binary_hunk = hunk.encode();
        }

        {
            let blobs = vec![make_blob(blob1_src), make_blob(blob2_src), make_blob(blob3_src)];
            let hunk = BlobWalHunk::new(brick_name, blobs, &hunk_flags);
            let BinaryHunk { hunk: binary_hunk, .. } = hunk.encode();

            let expected = vec![// header magic numbers
                                0x90,
                                0x7F,
                                // type = BlobWalHunk,
                                b'w',
                                // flags
                                0x00,
                                // brick name size, 6 in big-endian u16
                                0x00,
                                0x06,
                                // number of blobs, 3 in big-endian u16
                                0x00,
                                0x03,
                                // total blob size, 13 in big-endian u32
                                0x00,
                                0x00,
                                0x00,
                                0x0D,
                                // blobs
                                b'H',
                                b'e',
                                b'l',
                                b'l',
                                b'o',
                                b',',
                                b' ',
                                b'w',
                                b'o',
                                b'r',
                                b'l',
                                b'd',
                                b'!',
                                // footer magic numbers
                                0x07,
                                0xE3,
                                // checksum
                                0xB5,
                                0xDA,
                                0x44,
                                0x1C,
                                0xFE,
                                0x72,
                                0xAE,
                                0x04,
                                0x2E,
                                0xF4,
                                0xD2,
                                0xB1,
                                0x77,
                                0x42,
                                0x90,
                                0x7F,
                                0x67,
                                0x5D,
                                0xE4,
                                0xDA,
                                0x57,
                                0x46,
                                0x2D,
                                0x4C,
                                0x36,
                                0x09,
                                0xC2,
                                0xE2,
                                0xED,
                                0x75,
                                0x59,
                                0x70,
                                // brick name
                                b'b',
                                b'r',
                                b'i',
                                b'c',
                                b'k',
                                b'1',
                                // offset to blob1, 12 in big-endian u32
                                0x00,
                                0x00,
                                0x00,
                                0x0C,
                                // offset to blob2, 17 in big-endian u32
                                0x00,
                                0x00,
                                0x00,
                                0x11,
                                // offset to blob2, 19 in big-endian u32
                                0x00,
                                0x00,
                                0x00,
                                0x13,
                                // padding, total 80 bytes
                                0x00,
                                0x00,
                                0x00];
            assert_eq!(expected, binary_hunk);
            assert_eq!(80, binary_hunk.len());
        }

        {
            let blob = make_blob(blob1_src);
            let hunk = BlobSingleHunk::new(blob, &hunk_flags);
            let _binary_hunk = hunk.encode();
        }

        {
            // Zero-byte blob. NOTE: Hibari will not create blob at all for this case.
            let blobs = Vec::new();
            let hunk = BlobMultiHunk::new(blobs, &hunk_flags_no_checksum);
            let BinaryHunk { hunk: binary_hunk, .. } = hunk.encode();

            let expected = vec![// header magic numbers
                                0x90,
                                0x7F,
                                // type = BlobMultiHunk,
                                b'p',
                                // flags (no-checksum)
                                0x01,
                                // brick name size, always 0 for BlobMultiHunk
                                0x00,
                                0x00,
                                // number of blobs, 0 in big-endian u16
                                0x00,
                                0x00,
                                // total blob size, 0 in big-endian u32
                                0x00,
                                0x00,
                                0x00,
                                0x00,
                                // there is no blob to store
                                // footer magic numbers
                                0x07,
                                0xE3,
                                // no checksum
                                // no blob offset
                                // padding, total 16 bytes
                                0x00,
                                0x00];
            assert_eq!(expected, binary_hunk);
            assert_eq!(16, binary_hunk.len());
        }

        {
            let blobs = vec![make_blob(blob1_src), make_blob(blob2_src), make_blob(blob3_src)];
            let hunk = BlobMultiHunk::new(blobs, &hunk_flags);
            let _binary_hunk = hunk.encode();
        }
    }

    #[test]
    fn test_decode_hunks() {
        let _ = env_logger::init();

        let brick_name = "brick1";
        let blob1_src = b"Hello";
        let blob2_src = b", ";
        let blob3_src = b"world!";
        let hunk_flags: [HunkFlag; 0] = [];
        let _hunk_flags_no_checksum = [HunkFlag::NoChecksum];

        {
            let binary = vec![// header magic numbers
                              0x90,
                              0x7F,
                              // type = BlobWalHunk,
                              b'w',
                              // flags
                              0x00,
                              // brick name size, 6 in big-endian u16
                              0x00,
                              0x06,
                              // number of blobs, 3 in big-endian u16
                              0x00,
                              0x03,
                              // total blob size, 13 in big-endian u32
                              0x00,
                              0x00,
                              0x00,
                              0x0D,
                              // blobs
                              b'H',
                              b'e',
                              b'l',
                              b'l',
                              b'o',
                              b',',
                              b' ',
                              b'w',
                              b'o',
                              b'r',
                              b'l',
                              b'd',
                              b'!',
                              // footer magic numbers
                              0x07,
                              0xE3,
                              // checksum
                              0xB5,
                              0xDA,
                              0x44,
                              0x1C,
                              0xFE,
                              0x72,
                              0xAE,
                              0x04,
                              0x2E,
                              0xF4,
                              0xD2,
                              0xB1,
                              0x77,
                              0x42,
                              0x90,
                              0x7F,
                              0x67,
                              0x5D,
                              0xE4,
                              0xDA,
                              0x57,
                              0x46,
                              0x2D,
                              0x4C,
                              0x36,
                              0x09,
                              0xC2,
                              0xE2,
                              0xED,
                              0x75,
                              0x59,
                              0x70,
                              // brick name
                              b'b',
                              b'r',
                              b'i',
                              b'c',
                              b'k',
                              b'1',
                              // offset to blob1, 12 in big-endian u32
                              0x00,
                              0x00,
                              0x00,
                              0x0C,
                              // offset to blob2, 17 in big-endian u32
                              0x00,
                              0x00,
                              0x00,
                              0x11,
                              // offset to blob2, 19 in big-endian u32
                              0x00,
                              0x00,
                              0x00,
                              0x13,
                              // padding, total 80 bytes
                              0x00,
                              0x00,
                              0x00];
            assert_eq!(80, binary.len());

            match decode_hunks(&binary, 0) {
                Ok((boxed_hunks, _offset)) => {
                    assert_eq!(1, boxed_hunks.len());
                    if let &BoxedHunk::BlobWal(ref hunk) = &boxed_hunks[0] {
                        let blobs =
                            vec![make_blob(blob1_src), make_blob(blob2_src), make_blob(blob3_src)];
                        let expected = BlobWalHunk::new(brick_name, blobs, &hunk_flags);
                        assert_eq!(&expected, hunk);
                    } else {
                        panic!("boxed_hunk[0] is not a BlobWalHunk");
                    }
                }
                Err((ParseError, _offset)) => unreachable!(),
            }
        }
    }

    #[test]
    fn test_encode_and_decode_many_wal_hunks() {
        let _ = env_logger::init();

        let num_hunks = 1000;
        let brick_name = "brick1";
        let hunk_flags: [HunkFlag; 0] = [];

        fn make_blobs(i: usize) -> Vec<Blob> {
            let blob1 = format!("blob1_{:010}", i);
            let blob2 = format!("blob2_{:010}", i);
            let blob3 = format!("blob3_{:010}", i);
            let blob4 = format!("blob4_{:010}", i);
            vec![make_blob(blob1.as_bytes()),
                 make_blob(blob2.as_bytes()),
                 make_blob(blob3.as_bytes()),
                 make_blob(blob4.as_bytes())]
        }

        let expected_bin_size = {
            let HunkSize{raw_size, padding_size, ..} =
                calc_hunk_size(&HunkType::BlobWal,
                               &hunk_flags,
                               brick_name.as_bytes().len() as u16,
                               4,
                               16 * 4);
            (raw_size as usize + padding_size as usize) * num_hunks
        };

        assert!(expected_bin_size % 8 == 0);


        let mut hunks = Vec::with_capacity(expected_bin_size);

        // Encode everything.
        {
            let mut bin_size: usize = 0;

            for i in 0..num_hunks {
                let blobs = make_blobs(i);
                let hunk = BlobWalHunk::new(brick_name, blobs, &hunk_flags);
                let BinaryHunk {
                    hunk: mut binary_hunk, hunk_size, .. } = hunk.encode();
                hunks.append(&mut binary_hunk);
                bin_size += hunk_size as usize;
            }

            assert_eq!(bin_size, hunks.len());
            assert_eq!(expected_bin_size, hunks.len());
        }

        // Decode everything at once.
        match decode_hunks(&hunks[..], 0) {
            Err(_) => unreachable!(),
            Ok((boxed_hunks, offset)) => {
                assert_eq!(num_hunks, boxed_hunks.len());
                assert_eq!(expected_bin_size, offset);

                for (i, boxed_hunk) in boxed_hunks.iter().enumerate() {
                    if let &BoxedHunk::BlobWal(ref hunk) = boxed_hunk {
                        let expected_blobs = make_blobs(i);
                        assert_eq!(expected_blobs, hunk.blobs);
                    } else {
                        unreachable!();
                    }
                }
            }
        }

        // Decode using a fixed-size buffer.
        {
            // buffer is 5 bytes longer than the size to hold 10 hunks.
            let buffer_len = expected_bin_size / num_hunks * 10 + 5;
            let mut buffer = vec![0u8; buffer_len];
            let mut start_offset = 0;
            let mut hunk_count = 0;
            let mut hunk_number = 0;

            while start_offset < expected_bin_size {
                let end_offset = ::std::cmp::min(start_offset + buffer_len, expected_bin_size);
                let copy_size = end_offset - start_offset;
                (&mut buffer[..copy_size]).copy_from_slice(&hunks[start_offset..end_offset]);

                match decode_hunks(&buffer[..], 0) {
                    Err(_) => unreachable!(),
                    Ok((hunks, next_offset)) => {
                        hunk_count += hunks.len();
                        start_offset += next_offset;

                        for boxed_hunk in &hunks {
                            if let &BoxedHunk::BlobWal(ref hunk) = boxed_hunk {
                                let expected_blobs = make_blobs(hunk_number);
                                assert_eq!(expected_blobs, hunk.blobs);
                                hunk_number += 1;
                            } else {
                                unreachable!();
                            }
                        }
                    }
                }
            }

            assert_eq!(num_hunks, hunk_count);
        }
    }

    fn make_blob(src: &[u8]) -> Blob {
        let mut vec = Vec::with_capacity(src.len());
        vec.extend_from_slice(src);
        Blob(vec)
    }
}
