mod base_station;
mod city;
mod district;
mod idc;
pub mod meta;

use anyhow::*;
pub use base_station::BaseStationInfo;
pub use city::CityInfo;
pub use district::DistrictInfo;
pub use idc::IdcInfo;
pub use meta::Meta;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

pub struct Reader<'a> {
    /// The full database content, including the metadata header.
    data: Cow<'a, [u8]>,
    /// Offset of the node/payload area in `data` (i.e. the length of the
    /// metadata header). Kept as an offset instead of slicing so that
    /// constructing from borrowed data stays zero-copy.
    data_offset: usize,
    meta: Meta,
    v4offset: usize,
}

impl<'a> TryFrom<&'a [u8]> for Reader<'a> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> std::result::Result<Self, Self::Error> {
        Self::try_from(Cow::Borrowed(value))
    }
}

impl<'a> TryFrom<Cow<'a, [u8]>> for Reader<'a> {
    type Error = Error;

    fn try_from(value: Cow<'a, [u8]>) -> std::result::Result<Self, Self::Error> {
        ensure!(value.len() >= 4, "database too short: missing metadata length");
        let meta_length = u32::from_be_bytes((&value[..4]).try_into()?) as usize + 4;
        ensure!(
            value.len() >= meta_length,
            "database too short: incomplete metadata"
        );
        let meta = serde_json::from_str::<Meta>(
            std::str::from_utf8(&value[4..meta_length])
                .with_context(|| "metadata is not valid utf-8")?,
        )?;
        ensure!(
            meta.total_size + meta_length == value.len(),
            "database file size error"
        );
        let data = &value[meta_length..];
        let mut node = 0usize;
        for i in 0..96 {
            if node >= meta.node_count {
                break;
            }
            if i >= 80 {
                let off = node * 8 + 1 * 4;
                node = u32::from_be_bytes((&data[off..off + 4]).try_into()?) as usize;
            } else {
                let off = node * 8;
                node = u32::from_be_bytes((&data[off..off + 4]).try_into()?) as usize;
            }
        }

        Ok(Reader {
            data: value,
            data_offset: meta_length,
            meta,
            v4offset: node,
        })
    }
}

impl Reader<'static> {
    pub fn open_file<T: AsRef<Path>>(file: T) -> Result<Reader<'static>> {
        let path = file.as_ref();
        ensure!(path.exists(), "not found ipdb file:{:?}", path);
        let data = std::fs::read(path)?;

        Self::try_from(Cow::from(data))
    }
}

impl<'a> Reader<'a> {
    /// The node/payload area, skipping the metadata header.
    #[inline(always)]
    fn payload(&self) -> &[u8] {
        &self.data[self.data_offset..]
    }

    #[inline]
    fn resolve(&self, node: usize) -> Result<&str> {
        let data = self.payload();
        let resolved = node - self.meta.node_count + self.meta.node_count * 8;
        ensure!(
            resolved < data.len(),
            "database resolve error,resolved:{}>file length:{}",
            resolved,
            data.len()
        );
        let size =
            u32::from_be_bytes([0u8, 0u8, data[resolved], data[resolved + 1]]) as usize
                + resolved
                + 2;
        ensure!(
            data.len() > size,
            "database resolve error,size:{}>file length:{}",
            size,
            data.len()
        );
        unsafe { Ok(std::str::from_utf8_unchecked(&data[resolved + 2..size])) }
    }

    #[inline]
    fn read_node(&self, node: usize, index: usize) -> Result<usize> {
        let off = node * 8 + index * 4;
        Ok(u32::from_be_bytes((&self.payload()[off..off + 4]).try_into()?) as usize)
    }
    #[inline]
    fn find_node(&self, binary: &[u8]) -> Result<usize> {
        let mut node = 0;
        let bit = binary.len() * 8;
        if bit == 32 {
            node = self.v4offset;
        }
        for i in 0..bit {
            if node > self.meta.node_count {
                return Ok(node);
            }
            node = self.read_node(node, (1 & ((0xFF & binary[i / 8]) >> 7 - (i % 8))) as usize)?;
        }

        if node > self.meta.node_count {
            return Ok(node);
        } else {
            bail!("not found ip")
        }
    }

    #[inline(always)]
    pub fn is_ipv4(&self) -> bool {
        self.meta.ip_version & 0x01 == 0x01
    }

    #[inline(always)]
    pub fn is_ipv6(&self) -> bool {
        self.meta.ip_version & 0x02 == 0x02
    }

    #[inline]
    pub fn find(&self, addr: &str, language: &str) -> Result<Vec<&str>> {
        let addr = IpAddr::from_str(addr)?;
        ensure!(!self.meta.fields.is_empty(), "fields is empty");
        let off = *self
            .meta
            .languages
            .get(language)
            .ok_or_else(|| anyhow!("not found language:{}", language))?;
        let mut _ipv4_buff;
        let mut _ipv6_buff;
        let ipv = match &addr {
            IpAddr::V4(v) => {
                ensure!(self.is_ipv4(), "error:ipdb is ipv6");
                _ipv4_buff = v.octets();
                &_ipv4_buff[..]
            }
            IpAddr::V6(v) => {
                ensure!(self.is_ipv6(), "error:ipdb is ipv4");
                _ipv6_buff = v.octets();
                &_ipv6_buff[..]
            }
        };
        let node = self.find_node(ipv)?;
        let context = self.resolve(node)?;
        let sp: Vec<&str> = context.split('\t').skip(off).collect();
        Ok(sp)
    }

    #[inline]
    pub fn find_city_info(&self, addr: &str, language: &str) -> Result<CityInfo<'_>> {
        Ok(self.find(addr, language)?.into())
    }

    #[inline]
    pub fn find_district_info(&self, addr: &str, language: &str) -> Result<DistrictInfo<'_>> {
        Ok(self.find(addr, language)?.into())
    }

    #[inline]
    pub fn find_idc_info(&self, addr: &str, language: &str) -> Result<IdcInfo<'_>> {
        Ok(self.find(addr, language)?.into())
    }

    #[inline]
    pub fn find_base_station_info(
        &self,
        addr: &str,
        language: &str,
    ) -> Result<BaseStationInfo<'_>> {
        Ok(self.find(addr, language)?.into())
    }

    #[inline]
    pub fn find_map(&self, addr: &str, language: &str) -> Result<BTreeMap<&str, &str>> {
        let v = self.find(addr, language)?;
        let k = &self.meta.fields;
        let mut map: BTreeMap<&str, &str> = BTreeMap::new();
        for i in 0..v.len() {
            let value = v[i];
            let key = k.get(i).ok_or_else(|| anyhow!("keys len too small"))?;
            map.insert(key.as_str(), value);
        }
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal valid IPv4 ipdb database:
    /// a single-node trie (node_count = 1) whose both children point to one
    /// record containing "中国\t北京", so every IPv4 lookup resolves to it.
    fn build_test_db() -> Vec<u8> {
        let record = "中国\t北京".as_bytes();

        // payload layout:
        //   [0..8]   node 0: left child = 2, right child = 2 (2 > node_count => leaf)
        //   [8]      padding so that resolve(2) = 2 - 1 + 8 = 9 lands on the record
        //   [9..11]  record length (BE u16)
        //   [11..]   record bytes
        //   last     trailing padding byte (resolve requires data.len() > record end)
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.push(0);
        payload.extend_from_slice(&(record.len() as u16).to_be_bytes());
        payload.extend_from_slice(record);
        payload.push(0);

        let meta = format!(
            concat!(
                r#"{{"build":0,"ip_version":1,"node_count":1,"#,
                r#""languages":{{"CN":0}},"#,
                r#""fields":["country_name","region_name"],"#,
                r#""total_size":{}}}"#
            ),
            payload.len()
        );

        let mut buf = Vec::new();
        buf.extend_from_slice(&(meta.len() as u32).to_be_bytes());
        buf.extend_from_slice(meta.as_bytes());
        buf.extend_from_slice(&payload);
        buf
    }

    #[test]
    fn find_from_borrowed_data() {
        let db = build_test_db();
        let reader = Reader::try_from(&db[..]).unwrap();
        assert_eq!(reader.find("1.2.3.4", "CN").unwrap(), vec!["中国", "北京"]);
    }

    #[test]
    fn find_from_owned_data() {
        let db = build_test_db();
        let reader = Reader::try_from(Cow::from(db)).unwrap();
        assert_eq!(reader.find("1.2.3.4", "CN").unwrap(), vec!["中国", "北京"]);
    }

    #[test]
    fn find_map_from_borrowed_data() {
        let db = build_test_db();
        let reader = Reader::try_from(&db[..]).unwrap();
        let map = reader.find_map("1.2.3.4", "CN").unwrap();
        assert_eq!(map.get("country_name"), Some(&"中国"));
        assert_eq!(map.get("region_name"), Some(&"北京"));
    }

    #[test]
    fn short_input_returns_error_instead_of_panicking() {
        assert!(Reader::try_from(&[][..]).is_err());
        assert!(Reader::try_from(&[0u8, 0, 0][..]).is_err());
        // declared metadata length exceeds the actual buffer
        assert!(Reader::try_from(&[0u8, 0, 0, 100, b'{'][..]).is_err());
    }

    #[test]
    fn truncated_body_returns_error() {
        let mut db = build_test_db();
        db.pop();
        // total_size no longer matches
        assert!(Reader::try_from(&db[..]).is_err());
    }
}
