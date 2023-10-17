publish:
    cargo publish -p client
    cargo publish -p router

b:
    cargo build

f:
    rustfmt --config=max_width=1000 src/**/*.rs
    rustfmt src/**/*.rs
    cargo fix --lib --allow-dirty