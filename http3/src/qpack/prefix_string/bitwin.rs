#[derive(Debug, Default, PartialEq, Clone)]
pub struct BitWindow {
    pub byte: usize,
    pub bit: usize,
    pub count: usize,
}

impl BitWindow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn forwards(&mut self, step: usize) {
        self.bit += self.count;

        self.byte += self.bit / 8;
        self.bit %= 8;

        self.count = step;
    }

    pub fn end(&self) -> Option<usize> {
        self.byte
            .checked_mul(8)?
            .checked_add(self.bit)?
            .checked_add(self.count)
    }
}
