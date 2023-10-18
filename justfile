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
    for i in $(seq 2 3); do \
        sudo ifconfig lo0 alias 127.0.0.$i up; \
    done
    sudo RUST_LOG=debug cargo r -p cli