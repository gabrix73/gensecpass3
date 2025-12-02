# 🔐 gensecpass3

**Ultra-Secure Password Generator with Dual Physical Entropy Collection**

gensecpass3 generates cryptographically strong passwords by combining entropy from two independent physical sources: keyboard input and mouse movement. This dual-channel approach ensures true randomness that cannot be predicted or replicated.

## Features

- **Dual Entropy Sources**: Combines keyboard chaos + mouse movement for maximum unpredictability
- **Timing-Based Entropy**: Captures nanosecond-precision timing between events
- **Protected Memory**: Uses [memguard](https://github.com/awnumar/memguard) to prevent password exposure in RAM
- **Age Encryption**: Saves passwords encrypted with [age](https://age-encryption.org/) (scrypt)
- **Secure Wipe**: DoD 5220.22-M compliant 7-pass file destruction
- **Zero Dependencies at Runtime**: Single static binary

## Security Model

gensecpass3 addresses multiple threat vectors:

| Threat | Mitigation |
|--------|------------|
| Weak PRNG | Physical entropy from human input |
| Memory Forensics | memguard protected buffers with automatic wiping |
| Cold Boot Attacks | Immediate memory destruction on exit |
| File Recovery | DoD 5220.22-M secure wipe |

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/gensecpass3.git
cd gensecpass3

# Build
go mod tidy
go build -o gensecpass3 .

# Optional: Install system-wide
sudo mv gensecpass3 /usr/local/bin/
```

### Dependencies

- Go 1.21+
- [filippo.io/age](https://github.com/FiloSottile/age) - Modern encryption
- [github.com/awnumar/memguard](https://github.com/awnumar/memguard) - Secure memory
- [github.com/gdamore/tcell/v2](https://github.com/gdamore/tcell) - Terminal UI for mouse capture
- [golang.org/x/term](https://pkg.go.dev/golang.org/x/term) - Terminal raw mode

## Usage

### Generate Password (Interactive)

```bash
./gensecpass3
```

This launches the dual-challenge entropy collection:

1. **Challenge 1 - Keyboard Chaos**: Type randomly and chaotically
2. **Challenge 2 - Mouse Chaos**: Move mouse in random patterns, click, scroll

After collection, choose to save encrypted or display once.

### Options

```bash
# Custom password length (default: 16, range: 8-256)
./gensecpass3 -l 32

# Custom output file (default: password.txt.age)
./gensecpass3 -o mypass.age

# Verbose mode (shows entropy statistics)
./gensecpass3 -v

# Show version
./gensecpass3 -version
```

### Decrypt Saved Password

```bash
./gensecpass3 -decrypt -encfile password.txt.age
```

### Secure Wipe

Permanently destroy a file using DoD 5220.22-M standard (7-pass overwrite):

```bash
./gensecpass3 -wipe -wipefile sensitive.txt
```

## Entropy Collection Details

### Keyboard Challenge

- Captures raw keystrokes in terminal raw mode
- Records nanosecond timestamps between keypresses
- Adds both character value and timing delta to entropy pool
- Target: 512 bytes (~57 keystrokes with timing)

### Mouse Challenge

- Uses tcell for cross-platform mouse capture
- Collects X/Y coordinates of every movement
- Records click events (left, right, middle)
- Captures scroll wheel events
- Tracks timing between all events
- Visual feedback with progress bar
- Target: 512 bytes

### Entropy Combination

```
Final Seed = SHA256(
    SHA256(keyboard_data + keyboard_timings) ||
    SHA256(mouse_data + mouse_timings) ||
    crypto/rand(32 bytes)
)
```

The combination of:
- Human keyboard input (unpredictable characters + timing)
- Human mouse input (unpredictable coordinates + timing)
- System CSPRNG (crypto/rand)

Creates a seed that is computationally infeasible to predict or reproduce.

## Character Set

Generated passwords use 94 printable ASCII characters:

```
abcdefghijklmnopqrstuvwxyz
ABCDEFGHIJKLMNOPQRSTUVWXYZ
0123456789
!@#$%^&*()-_=+[]{}|;:,.<>?/
```

Entropy per character: ~6.55 bits

| Length | Entropy |
|--------|---------|
| 16 | ~104 bits |
| 24 | ~157 bits |
| 32 | ~209 bits |
| 64 | ~419 bits |

## Security Considerations

### Recommended Practices

- Run in a clean terminal without screen recording
- Use on a trusted, non-compromised system
- Don't run over SSH (timing data becomes network-observable)
- Ensure no keyloggers are present
- Use the encrypted save option for sensitive passwords

### Threat Model Limitations

This tool does NOT protect against:
- Compromised operating system kernel
- Hardware keyloggers
- Malicious terminal emulators
- Screen capture malware
- Physical observation during generation

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please ensure any PRs maintain the security-first approach:

1. No reduction in entropy quality
2. No logging of sensitive data
3. Proper memory handling for all secrets
4. Maintain offline-first design

## Acknowledgments

- [age](https://age-encryption.org/) by Filippo Valsorda
- [memguard](https://github.com/awnumar/memguard) by Awn Umar
- [tcell](https://github.com/gdamore/tcell) by Garrett D'Amore

---

**Remember**: A password generator is only as secure as the environment it runs in. Use responsibly.
