//! Do the columns agree? Each answered column is reduced to its RCODE and its answer RRsets
//! (owner lower-cased, type, canonical RDATA; TTL and order ignored; RRSIG, NSEC and NSEC3 left
//! out: signatures differ between signers and Windows never shows them). The most common of
//! these among the columns asked directly is the reference; every column that differs from it,
//! Windows included, is marked, and so are its records that the reference does not have.

use crate::query::{NSEC, NSEC3, RRSIG, Rr};
use std::collections::BTreeSet;

pub type Key = (Vec<u8>, u16, Vec<u8>);

/// What one column brings to the comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// Not answered yet.
    Pending,
    /// No answer at all (a timeout, a refused connection): left out.
    Failed,
    /// An answer: its RCODE and its answer section.
    Answer { rcode: u16, records: Vec<Rr> },
}

/// The key of one record, or None for DNSSEC metadata the comparison leaves out.
pub fn key(r: &Rr) -> Option<Key> {
    if matches!(r.rtype, RRSIG | NSEC | NSEC3) {
        return None;
    }
    let owner: Vec<u8> = r.owner.iter().flat_map(|l| std::iter::once(l.len() as u8).chain(l.iter().map(u8::to_ascii_lowercase))).collect();
    Some((owner, r.rtype, r.canon.clone()))
}

fn set_of(records: &[Rr]) -> BTreeSet<Key> {
    records.iter().filter_map(key).collect()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Verdict {
    /// Not every column has answered: no verdict yet (green waits for every answer).
    #[default]
    Waiting,
    /// This column gave no answer.
    NoAnswer,
    /// The same as the reference (or nothing to compare with).
    Agrees,
    /// Not the same: the answer records the reference lacks (their indexes), how many of the
    /// reference's this one lacks, and whether the RCODE differs.
    Differs { extra: Vec<usize>, missing: usize, rcode: bool },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Comparison {
    pub verdicts: Vec<Verdict>,
    /// The column whose answer is the reference (the first of the most common group).
    pub reference: Option<usize>,
    pub agree: usize,
    pub answered: usize,
    pub pending: usize,
}

impl Comparison {
    pub fn done(&self) -> bool {
        self.pending == 0
    }

    pub fn differing(&self) -> Vec<usize> {
        self.verdicts.iter().enumerate().filter(|(_, v)| matches!(v, Verdict::Differs { .. })).map(|(i, _)| i).collect()
    }
}

/// Compare the columns; `raw[i]` says column i was asked directly (not through Windows). Until
/// every column has answered or failed, every verdict waits.
pub fn compare(cols: &[Input], raw: &[bool]) -> Comparison {
    let pending = cols.iter().filter(|c| **c == Input::Pending).count();
    let answered = cols.iter().filter(|c| matches!(c, Input::Answer { .. })).count();
    let mut out = Comparison { verdicts: vec![Verdict::Waiting; cols.len()], reference: None, agree: 0, answered, pending };
    if pending > 0 {
        return out;
    }
    let sets: Vec<Option<(u16, BTreeSet<Key>)>> = cols
        .iter()
        .map(|c| match c {
            Input::Answer { rcode, records } => Some((*rcode, set_of(records))),
            _ => None,
        })
        .collect();
    // The most common answer among the raw columns; a tie goes to the group seen first. With no
    // raw answer, the first answer of any column.
    let mut best: Option<(usize, usize)> = None; // (count, first index)
    for (i, s) in sets.iter().enumerate() {
        let Some(s) = s else { continue };
        if !raw.get(i).copied().unwrap_or(true) {
            continue;
        }
        if sets[..i].iter().enumerate().any(|(j, t)| raw.get(j).copied().unwrap_or(true) && t.as_ref() == Some(s)) {
            continue; // counted with its first member
        }
        let n = sets.iter().enumerate().filter(|(j, t)| raw.get(*j).copied().unwrap_or(true) && t.as_ref() == Some(s)).count();
        if best.is_none_or(|(c, _)| n > c) {
            best = Some((n, i));
        }
    }
    let reference = best.map(|(_, i)| i).or_else(|| sets.iter().position(Option::is_some));
    out.reference = reference;
    let Some(r) = reference else {
        out.verdicts = cols.iter().map(|_| Verdict::NoAnswer).collect();
        return out;
    };
    let (ref_rcode, ref_set) = sets[r].clone().unwrap_or_default();
    for (i, c) in cols.iter().enumerate() {
        out.verdicts[i] = match (c, &sets[i]) {
            (Input::Answer { records, .. }, Some((rc, set))) => {
                if *rc == ref_rcode && *set == ref_set {
                    out.agree += 1;
                    Verdict::Agrees
                } else {
                    let extra = records.iter().enumerate().filter(|(_, rr)| key(rr).is_some_and(|k| !ref_set.contains(&k))).map(|(j, _)| j).collect();
                    let missing = ref_set.difference(set).count();
                    Verdict::Differs { extra, missing, rcode: *rc != ref_rcode }
                }
            }
            _ => Verdict::NoAnswer,
        };
    }
    out
}
