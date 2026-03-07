test flow is for coverage:

```bash
cargo llvm-cov nextest --ignore-filename-regex="rustc-" --html
```
