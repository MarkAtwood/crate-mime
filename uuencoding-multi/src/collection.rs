use std::collections::BTreeMap;

use crate::MultiUuError;

/// Maximum number of entries [`PartCollection::missing_parts`] returns.
const MISSING_PARTS_CAP: usize = 1_000_000;

/// A single collected part awaiting reassembly.
///
/// The caller is responsible for extracting `body_bytes` from the MIME or
/// plain-text message layer before constructing a `PartEntry`. This crate
/// treats `body_bytes` as an opaque UU-encoded byte sequence and passes it
/// directly to the `uuencoding` decoder.
///
/// # Example
///
/// ```
/// use uuencoding_multi::PartEntry;
///
/// let entry = PartEntry {
///     part_number: 1,
///     body_bytes: b"begin 644 file.bin\nend\n".to_vec(),
///     subject: Some("myfile.bin (1/3)".to_string()),
/// };
/// assert_eq!(entry.part_number, 1);
/// ```
#[derive(Clone, Debug)]
pub struct PartEntry {
    /// 1-based part index; 0 = TOC post.
    ///
    /// The value `0` is reserved for the optional table-of-contents post that
    /// Usenet series sometimes include as the first message. TOC parts do not
    /// contribute to the sequential `1..=total` count used during reassembly.
    pub part_number: u32,
    /// Raw bytes of this part's UU body, already extracted from the MIME layer
    /// by the caller. During reassembly the bodies of all parts are joined in
    /// part order and decoded together (see [`reassemble`][crate::reassemble()]).
    pub body_bytes: Vec<u8>,
    /// Original `Subject` header value, kept for diagnostics and logging.
    /// Not used during reassembly.
    pub subject: Option<String>,
}

/// Ordered, gap-aware collection of [`PartEntry`] values.
///
/// Parts are keyed by `part_number` and stored in a [`BTreeMap`] so iteration
/// is always in ascending order. A declared total can be provided up front via
/// [`PartCollection::with_total`]; if not, the collection tracks the highest
/// non-TOC part number it has seen so that
/// [`missing_parts`][Self::missing_parts] still works once a total is implied
/// by the highest part observed.
///
/// # Example: collecting three parts
///
/// ```
/// use uuencoding_multi::{PartCollection, PartEntry};
///
/// let mut coll = PartCollection::with_total(3);
/// for n in [1u32, 2, 3] {
///     coll.add(PartEntry { part_number: n, body_bytes: vec![], subject: None }).unwrap();
/// }
/// assert!(coll.is_complete());
/// ```
#[derive(Clone, Debug)]
pub struct PartCollection {
    /// Keyed by part_number.
    parts: BTreeMap<u32, PartEntry>,
    /// Declared total, if known. Updated upward as parts arrive if their
    /// part_number exceeds the current value.
    total: Option<u32>,
}

impl PartCollection {
    /// Create an empty collection with no declared total.
    ///
    /// The total will be inferred from the highest non-TOC `part_number` added
    /// via [`add`][Self::add]. Use [`with_total`][Self::with_total] when the
    /// total is known in advance (e.g. extracted from the subject line).
    ///
    /// # Warning: `is_complete()` after a single `add`
    ///
    /// Because the total is inferred from the highest part seen, adding a
    /// single part (e.g. part 1) immediately sets `total = Some(1)` and
    /// causes [`is_complete`][Self::is_complete] to return `true`. If the
    /// actual series has more parts, this is a false positive. Prefer
    /// [`with_total`][Self::with_total] whenever the total is known.
    ///
    /// # Example
    ///
    /// ```
    /// use uuencoding_multi::PartCollection;
    ///
    /// let coll = PartCollection::new();
    /// assert!(coll.is_empty());
    /// assert_eq!(coll.total(), None);
    /// ```
    pub fn new() -> Self {
        Self {
            parts: BTreeMap::new(),
            total: None,
        }
    }

    /// Create an empty collection with a pre-declared total.
    ///
    /// The `total` value sets the upper bound for gap detection: any part
    /// number in `1..=total` that has not been added will appear in
    /// [`missing_parts`][Self::missing_parts].
    ///
    /// If a later call to [`add`][Self::add] supplies a `part_number` greater
    /// than `total`, the stored total is bumped upward automatically.
    ///
    /// # Note: `total = 0`
    ///
    /// Passing `total = 0` is treated the same as calling [`new`][Self::new]:
    /// the total is considered unknown and will be inferred from the highest
    /// part number added. A subject like `"file.bin (3/0)"` produces
    /// `part_total = Some(0)`, which is nonsensical; passing that value here
    /// is safe because `0` is silently normalised to "unknown".
    ///
    /// # Example
    ///
    /// ```
    /// use uuencoding_multi::PartCollection;
    ///
    /// let coll = PartCollection::with_total(7);
    /// assert_eq!(coll.total(), Some(7));
    /// assert_eq!(coll.missing_parts().len(), 7); // parts 1–7 all missing
    /// ```
    ///
    /// ```
    /// use uuencoding_multi::PartCollection;
    ///
    /// // total = 0 is treated as unknown, same as PartCollection::new().
    /// let coll = PartCollection::with_total(0);
    /// assert_eq!(coll.total(), None);
    /// assert!(!coll.is_complete());
    /// ```
    pub fn with_total(total: u32) -> Self {
        Self {
            parts: BTreeMap::new(),
            total: if total == 0 { None } else { Some(total) },
        }
    }

    /// Add a part to the collection.
    ///
    /// Returns [`MultiUuError::DuplicatePart`] if a part with the same
    /// `part_number` is already present. The collection is left unchanged on
    /// error.
    ///
    /// If the incoming `part_number` is greater than the current `total`, the
    /// stored total is bumped upward so that [`missing_parts`][Self::missing_parts]
    /// always covers every number up to the highest seen. TOC parts
    /// (`part_number = 0`) do not affect the total.
    ///
    /// # Errors
    ///
    /// Returns [`MultiUuError::DuplicatePart`] when `part_number` is already
    /// present in the collection.
    ///
    /// # Example
    ///
    /// ```
    /// use uuencoding_multi::{PartCollection, PartEntry, MultiUuError};
    ///
    /// let mut coll = PartCollection::new();
    /// coll.add(PartEntry { part_number: 1, body_bytes: vec![], subject: None }).unwrap();
    ///
    /// // Adding the same part number again is an error.
    /// let err = coll.add(PartEntry { part_number: 1, body_bytes: vec![], subject: None })
    ///     .unwrap_err();
    /// assert!(matches!(err, MultiUuError::DuplicatePart { part_number: 1 }));
    /// ```
    pub fn add(&mut self, entry: PartEntry) -> Result<(), MultiUuError> {
        let pn = entry.part_number;
        if self.parts.contains_key(&pn) {
            return Err(MultiUuError::DuplicatePart { part_number: pn });
        }
        // Keep total at least as large as the highest part_number seen (for
        // non-TOC parts only — part 0 is the TOC and does not count toward the
        // sequential total).
        if pn > 0 {
            self.total = Some(match self.total {
                Some(t) => t.max(pn),
                None => pn,
            });
        }
        self.parts.insert(pn, entry);
        Ok(())
    }

    /// Returns the declared total part count, or the highest non-TOC part
    /// number seen if no explicit total was provided.
    ///
    /// Returns `None` only when the collection is empty and no total was set.
    ///
    /// # Example
    ///
    /// ```
    /// use uuencoding_multi::{PartCollection, PartEntry};
    ///
    /// let mut coll = PartCollection::new();
    /// assert_eq!(coll.total(), None);
    ///
    /// coll.add(PartEntry { part_number: 3, body_bytes: vec![], subject: None }).unwrap();
    /// assert_eq!(coll.total(), Some(3)); // inferred from highest part seen
    /// ```
    pub fn total(&self) -> Option<u32> {
        self.total
    }

    /// Iterator over the part numbers that are present, in ascending order.
    ///
    /// Includes the TOC part (`part_number = 0`) if one was added.
    ///
    /// # Example
    ///
    /// ```
    /// use uuencoding_multi::{PartCollection, PartEntry};
    ///
    /// let mut coll = PartCollection::new();
    /// coll.add(PartEntry { part_number: 3, body_bytes: vec![], subject: None }).unwrap();
    /// coll.add(PartEntry { part_number: 1, body_bytes: vec![], subject: None }).unwrap();
    ///
    /// let present: Vec<u32> = coll.present_parts().collect();
    /// assert_eq!(present, vec![1, 3]); // always ascending
    /// ```
    pub fn present_parts(&self) -> impl Iterator<Item = u32> + '_ {
        self.parts.keys().copied()
    }

    /// Sorted list of part numbers in `1..=total` that are absent from the
    /// collection.
    ///
    /// Returns an empty `Vec` when `total` is `None`.
    ///
    /// # Length cap
    ///
    /// At most the **first 1 000 000** missing part numbers are returned
    /// (4 MB), so that a hostile or bogus total such as `u32::MAX` cannot
    /// exhaust memory. Real series are far smaller, and
    /// [`parse_subject`][crate::parse_subject] never yields a total above
    /// 999 999, so the list is complete for any total it produces. When the
    /// list is non-empty, at least one part is missing either way. Use
    /// [`is_complete`][Self::is_complete] for a completeness check; it never
    /// allocates.
    ///
    /// Cost is O(present parts + returned length), not O(`total`).
    ///
    /// # Example
    ///
    /// ```
    /// use uuencoding_multi::{PartCollection, PartEntry};
    ///
    /// let mut coll = PartCollection::with_total(4);
    /// coll.add(PartEntry { part_number: 1, body_bytes: vec![], subject: None }).unwrap();
    /// coll.add(PartEntry { part_number: 3, body_bytes: vec![], subject: None }).unwrap();
    ///
    /// assert_eq!(coll.missing_parts(), vec![2, 4]);
    /// ```
    pub fn missing_parts(&self) -> Vec<u32> {
        let Some(total) = self.total else {
            return Vec::new();
        };
        let mut missing = Vec::new();
        // Walk the gaps between consecutive present keys in 1..=total.
        // `next` is u64 so that `key + 1` cannot overflow for key == u32::MAX.
        let mut next: u64 = 1;
        let present = self.parts.range(1..=total).map(|(&k, _)| u64::from(k));
        for gap_end in present.chain(std::iter::once(u64::from(total) + 1)) {
            for n in next..gap_end {
                if missing.len() >= MISSING_PARTS_CAP {
                    return missing;
                }
                // n < gap_end <= total + 1, so n <= total fits in u32.
                missing.push(n as u32);
            }
            next = gap_end + 1;
        }
        missing
    }

    /// Returns `true` iff the total is known and every part in `1..=total` is
    /// present.
    ///
    /// Always returns `false` when `total` is `None`, even if parts have been
    /// added.
    ///
    /// # Warning: auto-inferred total
    ///
    /// When a collection was created with [`new`][Self::new] (no declared
    /// total), the total is inferred as the highest part number seen. Adding
    /// only part 1 sets `total = Some(1)` and this function immediately returns
    /// `true`, even if the series actually has more parts. Use
    /// [`with_total`][Self::with_total] to set the authoritative total.
    ///
    /// # Example
    ///
    /// ```
    /// use uuencoding_multi::{PartCollection, PartEntry};
    ///
    /// let mut coll = PartCollection::with_total(2);
    /// coll.add(PartEntry { part_number: 1, body_bytes: vec![], subject: None }).unwrap();
    /// assert!(!coll.is_complete());
    ///
    /// coll.add(PartEntry { part_number: 2, body_bytes: vec![], subject: None }).unwrap();
    /// assert!(coll.is_complete());
    /// ```
    pub fn is_complete(&self) -> bool {
        match self.total {
            None => false,
            // Keys are unique, so all of 1..=t are present iff the map holds
            // exactly t keys in that range. No allocation; O(present parts).
            Some(t) => self.parts.range(1..=t).count() as u64 == u64::from(t),
        }
    }

    /// Returns the TOC part (part number 0) if one was added, `None` otherwise.
    ///
    /// The TOC part body can be passed to [`parse_toc`][crate::parse_toc] to
    /// extract file metadata.
    ///
    /// # Example
    ///
    /// ```
    /// use uuencoding_multi::{PartCollection, PartEntry};
    ///
    /// let mut coll = PartCollection::new();
    /// assert!(coll.toc_part().is_none());
    ///
    /// coll.add(PartEntry { part_number: 0, body_bytes: b"toc".to_vec(), subject: None }).unwrap();
    /// assert!(coll.toc_part().is_some());
    /// ```
    pub fn toc_part(&self) -> Option<&PartEntry> {
        self.parts.get(&0)
    }

    /// Look up a part by its part number.
    ///
    /// Returns `None` if the part is not present in the collection. Valid for
    /// any part number including `0` (TOC).
    ///
    /// # Example
    ///
    /// ```
    /// use uuencoding_multi::{PartCollection, PartEntry};
    ///
    /// let mut coll = PartCollection::new();
    /// coll.add(PartEntry { part_number: 2, body_bytes: b"data".to_vec(), subject: None }).unwrap();
    ///
    /// assert!(coll.get(2).is_some());
    /// assert!(coll.get(1).is_none());
    /// ```
    pub fn get(&self, part_number: u32) -> Option<&PartEntry> {
        self.parts.get(&part_number)
    }

    /// Number of entries currently in the collection, including the TOC part
    /// (`part_number = 0`) if present.
    ///
    /// # Example
    ///
    /// ```
    /// use uuencoding_multi::{PartCollection, PartEntry};
    ///
    /// let mut coll = PartCollection::new();
    /// assert_eq!(coll.len(), 0);
    ///
    /// coll.add(PartEntry { part_number: 1, body_bytes: vec![], subject: None }).unwrap();
    /// assert_eq!(coll.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.parts.len()
    }

    /// Returns `true` iff no parts have been added.
    ///
    /// # Example
    ///
    /// ```
    /// use uuencoding_multi::PartCollection;
    ///
    /// let coll = PartCollection::new();
    /// assert!(coll.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }
}

impl Default for PartCollection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part(n: u32) -> PartEntry {
        PartEntry {
            part_number: n,
            body_bytes: vec![],
            subject: None,
        }
    }

    #[test]
    fn out_of_order_insertion_sorted() {
        let mut c = PartCollection::new();
        c.add(PartEntry {
            part_number: 3,
            body_bytes: vec![],
            subject: None,
        })
        .unwrap();
        c.add(PartEntry {
            part_number: 1,
            body_bytes: vec![],
            subject: None,
        })
        .unwrap();
        let got: Vec<u32> = c.present_parts().collect();
        assert_eq!(got, vec![1, 3]);
    }

    #[test]
    fn gap_detection() {
        let mut c = PartCollection::with_total(4);
        c.add(part(1)).unwrap();
        c.add(part(2)).unwrap();
        c.add(part(4)).unwrap();
        assert_eq!(c.missing_parts(), vec![3]);
    }

    #[test]
    fn duplicate_returns_error() {
        let mut c = PartCollection::new();
        c.add(part(1)).unwrap();
        assert!(matches!(
            c.add(part(1)),
            Err(MultiUuError::DuplicatePart { part_number: 1 })
        ));
    }

    #[test]
    fn is_complete_when_all_present() {
        let mut c = PartCollection::with_total(2);
        c.add(part(1)).unwrap();
        c.add(part(2)).unwrap();
        assert!(c.is_complete());
    }

    /// `is_complete()` returns `false` when there is a gap: parts 1 and 3
    /// are present (total inferred as 3) but part 2 is missing.
    #[test]
    fn is_complete_false_with_gap() {
        let mut c = PartCollection::new();
        c.add(part(1)).unwrap();
        c.add(part(3)).unwrap(); // total bumps to 3; part 2 is missing
        assert!(!c.is_complete());
        assert_eq!(c.missing_parts(), vec![2]);
    }

    /// `is_complete()` returns `false` when the total is genuinely unknown
    /// (empty collection with no declared total).
    #[test]
    fn is_complete_false_when_total_unknown() {
        let c = PartCollection::new();
        assert_eq!(c.total(), None, "empty collection has no total");
        assert!(!c.is_complete(), "cannot be complete without a known total");
    }

    #[test]
    fn toc_part_returned() {
        let mut c = PartCollection::new();
        c.add(PartEntry {
            part_number: 0,
            body_bytes: b"toc".to_vec(),
            subject: None,
        })
        .unwrap();
        assert!(c.toc_part().is_some());
    }

    #[test]
    fn len_and_is_empty() {
        let mut c = PartCollection::new();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
        c.add(part(1)).unwrap();
        assert!(!c.is_empty());
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn missing_parts_empty_when_no_total() {
        let c = PartCollection::new();
        assert_eq!(c.missing_parts(), vec![] as Vec<u32>);
    }

    #[test]
    fn with_total_sets_total() {
        let c = PartCollection::with_total(5);
        assert_eq!(c.total(), Some(5));
    }

    #[test]
    fn with_total_zero_treated_as_unknown() {
        // with_total(0) must behave like new(): total unknown, is_complete false.
        let c = PartCollection::with_total(0);
        assert_eq!(c.total(), None);
        assert!(!c.is_complete());
        assert!(c.missing_parts().is_empty());
    }

    #[test]
    fn add_bumps_total_upward() {
        let mut c = PartCollection::with_total(3);
        c.add(part(5)).unwrap(); // exceeds declared total
        assert_eq!(c.total(), Some(5));
    }

    #[test]
    fn toc_does_not_affect_total() {
        let mut c = PartCollection::new();
        c.add(PartEntry {
            part_number: 0,
            body_bytes: vec![],
            subject: None,
        })
        .unwrap();
        // Part 0 (TOC) must not cause total to be set to 0.
        assert_eq!(c.total(), None);
    }

    #[test]
    fn default_is_same_as_new() {
        let c: PartCollection = Default::default();
        assert!(c.is_empty());
        assert_eq!(c.total(), None);
    }

    /// Documented footgun: adding a single part to a no-total collection
    /// infers total as the highest part number seen (1), so `is_complete()`
    /// returns `true` immediately. This is intentional behavior — the
    /// collection has no way to know that more parts exist. Callers should
    /// use `with_total()` when the total is known.
    ///
    /// See doc warnings on `PartCollection::new()` and `is_complete()`.
    #[test]
    fn single_part_no_total_infers_complete() {
        let mut c = PartCollection::new();
        assert_eq!(c.total(), None, "no total before any parts added");
        assert!(!c.is_complete(), "cannot be complete without a total");

        c.add(part(1)).unwrap();

        assert_eq!(c.total(), Some(1), "total inferred from highest part seen");
        assert!(c.missing_parts().is_empty(), "no gaps in 1..=1");
        assert!(
            c.is_complete(),
            "single part in a no-total collection is considered complete"
        );
    }

    /// A bogus part number of u32::MAX must not make is_complete or
    /// missing_parts allocate 4 GiB (this used to abort the process).
    #[test]
    fn huge_part_number_is_bounded() {
        let mut c = PartCollection::new();
        c.add(part(u32::MAX)).unwrap();
        assert_eq!(c.total(), Some(u32::MAX));
        assert!(!c.is_complete());

        let missing = c.missing_parts();
        assert_eq!(missing.len(), super::MISSING_PARTS_CAP);
        assert_eq!(&missing[..3], &[1, 2, 3]);
        assert_eq!(*missing.last().unwrap(), 1_000_000);
    }

    #[test]
    fn huge_total_with_low_parts_present() {
        let mut c = PartCollection::with_total(u32::MAX);
        c.add(part(1)).unwrap();
        c.add(part(3)).unwrap();
        assert!(!c.is_complete());
        let missing = c.missing_parts();
        assert_eq!(missing.len(), super::MISSING_PARTS_CAP);
        assert_eq!(&missing[..3], &[2, 4, 5]);
    }

    /// Gaps at the start, middle and end, plus a TOC part that must be
    /// ignored; compared with the obvious definition.
    #[test]
    fn missing_parts_matches_naive_definition() {
        let present = [0u32, 3, 4, 7, 10];
        let mut c = PartCollection::with_total(12);
        for &n in &present {
            c.add(part(n)).unwrap();
        }
        let naive: Vec<u32> = (1..=12).filter(|n| !present.contains(n)).collect();
        assert_eq!(c.missing_parts(), naive);
        assert_eq!(c.missing_parts(), vec![1, 2, 5, 6, 8, 9, 11, 12]);
        assert!(!c.is_complete());
    }

    #[test]
    fn complete_with_toc_and_max_part() {
        let mut c = PartCollection::with_total(2);
        c.add(part(0)).unwrap();
        c.add(part(1)).unwrap();
        c.add(part(2)).unwrap();
        assert!(c.is_complete());
        assert!(c.missing_parts().is_empty());
    }
}
