publish:
    cargo publish -p client
    cargo publish -p router

b:
    cargo build

f:
    rustfmt --config=max_width=1000 src/**/*.rs
    rustfmt src/**/*.rs
    cargo fix --lib --allow-dirty
cli:
    sudo ifconfig lo0 alias 127.0.0.2 up
    sudo RUST_LOG=debug cargo r -p cli