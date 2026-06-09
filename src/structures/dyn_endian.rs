use super::Endianness;

macro_rules! dyn_endian_ty {
    ($($vis:vis struct $name:ident($underlying:ty));* $(;)?) => {
        $(
        #[derive(Copy, Clone, PartialEq, Eq, zerocopy::FromBytes, zerocopy::KnownLayout, zerocopy::Unaligned, zerocopy::Immutable)]
        #[repr(transparent)]
        $vis struct $name([u8; size_of::<$underlying>()]);

        impl $name {
            #[inline]
            #[allow(unused)]
            $vis const fn new(value: $underlying, endianness: Endianness) -> Self {
                match endianness {
                    Endianness::Little => Self(value.to_le_bytes()),
                    Endianness::Big => Self(value.to_be_bytes()),
                }
            }

            #[inline]
            #[allow(unused)]
            $vis const fn get(&self, endianness: Endianness) -> $underlying {
                match endianness {
                    Endianness::Little => <$underlying>::from_le_bytes(self.0),
                    Endianness::Big => <$underlying>::from_be_bytes(self.0),
                }
            }
        }
        )*
    };
}

dyn_endian_ty! {
    pub struct U16(u16);
    pub struct U32(u32);
    pub struct U64(u64);
}
