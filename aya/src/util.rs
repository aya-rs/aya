use std::{fs, io, str::FromStr};

const ONLINE_CPUS: &str = "/sys/devices/system/cpu/online";

pub fn online_cpus() -> Result<Vec<u32>, io::Error> {
    let data = fs::read_to_string(ONLINE_CPUS)?;
    parse_online_cpus(data.trim()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("unexpected {} format", ONLINE_CPUS),
        )
    })
}

fn parse_online_cpus(data: &str) -> Result<Vec<u32>, ()> {
    let mut cpus = Vec::new();
    for range in data.split(',') {
        cpus.extend({
            match range
                .splitn(2, '-')
                .map(u32::from_str)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ())?
                .as_slice()
            {
                &[] | &[_, _, _, ..] => return Err(()),
                &[start] => start..=start,
                &[start, end] => start..=end,
            }
        })
    }

    Ok(cpus)
}

#[cfg(test)]
mod tests {
    use std::iter::FromIterator;

    use super::*;

    #[test]
    fn test_parse_online_cpus() {
        assert_eq!(parse_online_cpus("0").unwrap(), vec![0]);
        assert_eq!(parse_online_cpus("0,1").unwrap(), vec![0, 1]);
        assert_eq!(parse_online_cpus("0,1,2").unwrap(), vec![0, 1, 2]);
        assert_eq!(parse_online_cpus("0-7").unwrap(), Vec::from_iter(0..=7));
        assert_eq!(parse_online_cpus("0-3,4-7").unwrap(), Vec::from_iter(0..=7));
        assert_eq!(parse_online_cpus("0-5,6,7").unwrap(), Vec::from_iter(0..=7));
        assert!(parse_online_cpus("").is_err());
        assert!(parse_online_cpus("0-1,2-").is_err());
        assert!(parse_online_cpus("foo").is_err());
    }
}
