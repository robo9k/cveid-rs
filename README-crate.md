Typesafe Common Vulnerabilities and Exposures (CVE) Identifier

```rust
use cve_id::{CveId, CveYear};

fn cveid_example() -> Result<(), Box<dyn std::error::Error>> {
    let cve_id = CveId::from_str("CVE-1999-0001")?;

    assert_eq!(cve_id.year(), 1999);
    assert_eq!(cve_id.number(), 1);
    assert_eq!(cve_id.to_string(), "CVE-1999-0001");

    const CVE_TEST_YEAR: CveYear = {
        let Ok(year) = CveYear::new(1900) else {
            panic!("not a valid CVE year")
        };
        year
    };
    const CVE_TEST_ID: CveId = CveId::new(CVE_TEST_YEAR, 42);
    assert!(CVE_TEST_ID.is_example_or_test());

    Ok(())
}
```
