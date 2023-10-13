publish:
    cargo publish -p client
    cargo publish -p router

b:
    cargo build

f:
    # first format with a super high line width
    rustfmt --config=max_width=1000 src/**/*.rs
    # then format with the default line width
    rustfmt src/**/*.rs