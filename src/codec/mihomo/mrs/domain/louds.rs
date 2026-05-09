pub(super) fn set_bit(bitmap: &mut Vec<u64>, index: usize, value: u64) {
    while index >> 6 >= bitmap.len() {
        bitmap.push(0);
    }
    bitmap[index >> 6] |= value << (index & 63);
}

pub(super) fn get_bit(bitmap: &[u64], index: usize) -> u64 {
    bitmap[index >> 6] & (1 << (index & 63))
}

pub(super) struct LoudsIndex<'a> {
    words: &'a [u64],
    ones_before_word: Vec<usize>,
    sampled_one_positions: Vec<u32>,
}

impl<'a> LoudsIndex<'a> {
    const SELECT_SAMPLE_STEP: usize = 4;

    pub(super) fn new(bitmap: &'a [u64]) -> Self {
        let mut ones_before_word = Vec::with_capacity(bitmap.len() + 1);
        let mut sampled_one_positions = Vec::new();
        let mut ones = 0usize;
        for (word_index, word) in bitmap.iter().copied().enumerate() {
            ones_before_word.push(ones);
            let mut word_bits = word;
            while word_bits != 0 {
                let bit = word_bits.trailing_zeros() as usize;
                if ones.is_multiple_of(Self::SELECT_SAMPLE_STEP) {
                    sampled_one_positions.push((word_index * 64 + bit) as u32);
                }
                word_bits &= word_bits - 1;
                ones += 1;
            }
        }
        ones_before_word.push(ones);
        Self {
            words: bitmap,
            ones_before_word,
            sampled_one_positions,
        }
    }

    pub(super) fn count_zeros(&self, index: usize) -> usize {
        index - self.count_ones_before(index)
    }

    pub(super) fn select_ith_one(&self, target: usize) -> usize {
        let sample_index = target / Self::SELECT_SAMPLE_STEP;
        let mut position = self.sampled_one_positions[sample_index] as usize;
        let mut remaining = target - sample_index * Self::SELECT_SAMPLE_STEP;
        while remaining > 0 {
            position = next_one_position(self.words, position + 1);
            remaining -= 1;
        }
        position
    }

    fn count_ones_before(&self, index: usize) -> usize {
        let word = index >> 6;
        let bit = index & 63;
        let before = self.ones_before_word[word];
        if bit == 0 {
            return before;
        }
        let mask = (1u64 << bit) - 1;
        before + (self.words[word] & mask).count_ones() as usize
    }
}

fn next_one_position(words: &[u64], start: usize) -> usize {
    let mut word_index = start >> 6;
    let bit = start & 63;
    let mut word = words[word_index] & (!0u64 << bit);
    loop {
        if word != 0 {
            return word_index * 64 + word.trailing_zeros() as usize;
        }
        word_index += 1;
        word = words[word_index];
    }
}
