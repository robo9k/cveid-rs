Typesafe Common Vulnerabilities and Exposures (CVE) Identifier

```rust
use cve_id::CveId;

fn cveid_example() -> Result<(), Box<dyn std::error::Error>> {
    let cve_id = CveId::from_str("CVE-1999-0001")?;

    assert_eq!(cve_id.year(), 1999);
    assert_eq!(cve_id.number(), 1);
    assert_eq!(cve_id.to_string(), "CVE-1999-0001");

    const TEST_CVE_ID: CveId = CveId::new(1900, 424242);
    assert!(TEST_CVE_ID.is_example_or_test());

    Ok(())
}
```
