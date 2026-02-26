
use core::ops::{Deref, DerefMut};
pub struct Builder<T>(T);

impl<T> Builder<T> {
    pub fn finish(self) -> T {
        self.0
    }
}

impl<T> From<T> for Builder<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> Deref for Builder<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Builder<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

