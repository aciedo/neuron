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
    for i in $(seq 2 100); do \
        sudo ifconfig lo0 alias 127.0.0.$i up; \
    done
    cargo b -p cli
    sudo RUST_LOG=debug ./target/debug/cli