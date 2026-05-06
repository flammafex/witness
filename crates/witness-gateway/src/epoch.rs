pub fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_secs_returns_reasonable_value() {
        let now = epoch_secs();
        assert!(
            now > 1_577_836_800,
            "epoch_secs() = {} should be greater than Jan 1, 2020",
            now
        );
    }

    #[test]
    fn test_epoch_secs_does_not_panic() {
        let result = std::panic::catch_unwind(epoch_secs);
        assert!(result.is_ok(), "epoch_secs() should not panic");
    }
}
